import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * Issue #65 asks for a paste into an Excalidraw drawing to spawn the `${prompt}` box. This test pins
 * the boundary that answers it: `shouldRenameAttachmentsCreatedByOtherPlugins` -- the opt-in added for
 * issue #59 -- deliberately does NOTHING when the file in front of the user is one the user has listed
 * in `treatAsAttachmentExtensions`, which by default is exactly `.excalidraw.md`.
 *
 * That is not an oversight to be fixed by widening the gate. Excalidraw ships `compress: true`, so a
 * drawing's reference to a pasted image lives inside a `compressed-json` block: Obsidian never indexes
 * it, and neither `fileManager.renameFile` nor this plugin can rewrite it. Renaming such an image would
 * leave the drawing pointing at a path that no longer exists, silently. The handler declining is the
 * safe answer, and this test exists so a later change cannot quietly turn it into an unsafe one.
 *
 * Excalidraw itself is NOT installed here, and does not need to be: the gate under test is the plugin's
 * own `treatAsAttachmentExtensions` / `isNoteEx` pair, reached with a plain `.excalidraw.md` file open.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const WAIT_TIMEOUT_IN_MILLISECONDS = 30_000;

interface ProbeResult {
  readonly attachmentPathAfterDrawing: string;
  readonly attachmentPathAfterNote: string;
  readonly probesFound: boolean;
}

describe('An attachment written by another plugin while a drawing is open is left alone (issue #65)', () => {
  it('renames it for a normal note but not for a file treated as an attachment', async () => {
    const result = await evalInObsidian({
      async callback({ app, pluginId, waitTimeoutInMilliseconds }): Promise<ProbeResult> {
        // Module-scope constants are not captured by the serialized closure, so it lives here.
        const SETTLE_DELAY_IN_MILLISECONDS = 3000;

        interface OtherPluginSettings {
          attachmentFolderPath: string;
          shouldRenameAttachmentsCreatedByOtherPlugins: boolean;
        }

        /*
         * `treatAsAttachmentExtensions` belongs to Advanced Rename and Delete Handler since 12.0.0, and
         * this plugin no longer reads the array at all — it asks `isTreatedAsAttachment(path)`, so the
         * matching lives in one place across two bundled copies of the library. What this test pins is
         * therefore the PREDICATE's answer, supplied by a stub parked on the read-back component's live
         * ref rather than by installing the other plugin into the vault.
         */
        interface HandedOverProvider {
          getSettings(): Record<string, unknown>;
          isPathIgnored(path: string): boolean;
          isTreatedAsAttachment(path: string): boolean;
        }

        interface HandedOverProviderRef {
          value: HandedOverProvider | null;
        }

        interface HandedOverSettingsHolder {
          apiRef: HandedOverProviderRef | null;
        }

        function isOtherPluginSettings(value: unknown): value is OtherPluginSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldRenameAttachmentsCreatedByOtherPlugins'] === 'boolean'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        function isHandedOverSettingsHolder(value: unknown): value is HandedOverSettingsHolder {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && 'apiRef' in record
            && typeof record['isPathIgnored'] === 'function'
            && typeof record['isTreatedAsAttachment'] === 'function';
        }

        // Neither the settings nor the read-back component is exposed publicly, so both are located by
        // Walking the plugin's component tree.
        function findInPluginTree<T>(match: (record: Record<string, unknown>) => null | T): null | T {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [app.plugins.getPlugin(pluginId)];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            const matched = match(record);
            if (matched !== null) {
              return matched;
            }
            let values: unknown[] = [];
            if (Array.isArray(current)) {
              values = current;
            } else if (current instanceof Map) {
              values = [...current.values()];
            } else {
              for (const [key, value] of Object.entries(record)) {
                if (!block.has(key)) {
                  values.push(value);
                }
              }
            }
            for (const value of values) {
              if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
                queue.push(value);
              }
            }
          }
          return null;
        }

        const foundSettings = findInPluginTree((record) => isOtherPluginSettings(record['settings']) ? record['settings'] : null);
        const foundHolder = findInPluginTree((record) => isHandedOverSettingsHolder(record) ? record : null);
        if (!foundSettings || !foundHolder) {
          return { attachmentPathAfterDrawing: '', attachmentPathAfterNote: '', probesFound: false };
        }
        const settings: OtherPluginSettings = foundSettings;
        const holder: HandedOverSettingsHolder = foundHolder;

        const priorFolderPath = settings.attachmentFolderPath;
        const wasRenamingOtherPlugins = settings.shouldRenameAttachmentsCreatedByOtherPlugins;
        const priorApiRef = holder.apiRef;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const notePath = `eco-note-${stamp}.md`;
        const drawingPath = `eco-drawing-${stamp}.excalidraw.md`;
        const createdPaths: string[] = [];

        async function trashIfExists(path: string): Promise<void> {
          const existing = app.vault.getAbstractFileByPath(path);
          if (existing) {
            await app.fileManager.trashFile(existing);
          }
        }

        /*
         * Writes an attachment the way a third-party plugin does -- straight to disk, never through
         * `app.saveAttachment` -- while `ownerPath` is the open file, then reports where it ended up.
         */
        async function writeForeignAttachment(ownerPath: string, imageName: string, shouldExpectRelocation: boolean): Promise<string> {
          const owner = app.vault.getFileByPath(ownerPath);
          if (owner) {
            await app.workspace.getLeaf(false).openFile(owner);
          }
          await sleep(SETTLE_DELAY_IN_MILLISECONDS);

          // The handler renames as well as moves, so the file cannot be found again by its original
          // Name. Snapshot the vault instead and report whichever path appeared.
          const pathsBefore = new Set(app.vault.getFiles().map((file) => file.path));
          await app.vault.createBinary(imageName, new ArrayBuffer(4));
          createdPaths.push(imageName);

          if (shouldExpectRelocation) {
            /*
             * Wait for the additions to STOP CHANGING, not merely to appear. The handler moves the file
             * and then renames it, so a poll that fires on "something new exists" catches an
             * intermediate path -- and the final one then materializes during the NEXT phase, where it
             * is counted as that phase's addition. That is not hypothetical: it is exactly how this
             * test reported the first phase's file as the second phase's result.
             *
             * Settling here also makes the two phases independent, which is what the fixed settle
             * below relies on.
             */
            const STABLE_POLL_INTERVAL_IN_MILLISECONDS = 300;
            const REQUIRED_STABLE_POLLS = 3;
            let previousKey = '';
            let stablePolls = 0;
            let isSettled = false;
            const deadline = Date.now() + waitTimeoutInMilliseconds;
            while (Date.now() < deadline) {
              const current = app.vault.getFiles().map((file) => file.path).filter((path) => !pathsBefore.has(path)).sort();
              const key = current.join('|');
              const hasRelocated = current.length > 0 && !current.includes(imageName);
              if (key === previousKey && hasRelocated) {
                stablePolls++;
                if (stablePolls >= REQUIRED_STABLE_POLLS) {
                  isSettled = true;
                  break;
                }
              } else {
                stablePolls = 0;
                previousKey = key;
              }
              await sleep(STABLE_POLL_INTERVAL_IN_MILLISECONDS);
            }

            /*
             * Falling out of the loop unsettled used to be silent, and that silence is precisely the
             * Cross-phase leak the comment above warns about: this phase's file materializes during the
             * NEXT phase and is counted as its addition, which the next phase then reports as a moved
             * File where it asserts nothing moved. Say so here instead, naming the phase that stalled.
             */
            if (!isSettled) {
              throw new Error(`the relocation of ${imageName} never settled within ${String(waitTimeoutInMilliseconds)}ms`);
            }
          } else {
            // Nothing should happen here, and absence cannot be polled for -- give the handler its
            // Whole freshness window to act, then assert that it did not.
            await sleep(SETTLE_DELAY_IN_MILLISECONDS);
          }

          const added = app.vault.getFiles().map((file) => file.path).filter((path) => !pathsBefore.has(path));
          createdPaths.push(...added);
          return added.length === 1 ? added[0] ?? '' : `UNEXPECTED:${added.join(',')}`;
        }

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './eco-assets/${noteFileName}';
          settings.shouldRenameAttachmentsCreatedByOtherPlugins = true;
          holder.apiRef = {
            value: {
              getSettings: (): Record<string, unknown> => ({
                emptyFolderBehavior: 'DeleteWithEmptyParents',
                notePriorities: [],
                shouldRenameAttachmentFiles: false,
                treatAsAttachmentExtensions: ['.excalidraw.md']
              }),
              isPathIgnored: (): boolean => false,
              isTreatedAsAttachment: (path: string): boolean => path.endsWith('.excalidraw.md')
            }
          };

          await app.vault.create(notePath, 'body\n');
          createdPaths.push(notePath);
          await app.vault.create(drawingPath, 'drawing\n');
          createdPaths.push(drawingPath);

          const attachmentPathAfterNote = await writeForeignAttachment(notePath, `eco-a-${stamp}.png`, true);
          const attachmentPathAfterDrawing = await writeForeignAttachment(drawingPath, `eco-b-${stamp}.png`, false);

          return { attachmentPathAfterDrawing, attachmentPathAfterNote, probesFound: true };
        } finally {
          settings.attachmentFolderPath = priorFolderPath;
          settings.shouldRenameAttachmentsCreatedByOtherPlugins = wasRenamingOtherPlugins;
          holder.apiRef = priorApiRef;
          for (const path of createdPaths.reverse()) {
            await trashIfExists(path);
          }
        }
      },
      input: {
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // With a normal note open, the opt-in does its job: the foreign write is filed under the note.
    // Moved AND renamed: the file name is the plugin's `generatedAttachmentFileName`, not the one the
    // Foreign plugin wrote, which is exactly what the reporter wants for a drawing.
    expect(result.attachmentPathAfterNote).toMatch(/^eco-assets\/eco-note-[^/]+\/[^/]+\.png$/);
    expect(result.attachmentPathAfterNote).not.toContain('eco-a-');

    // With a file the user treats as an attachment open, it declines and leaves the file at the root.
    // This is the answer to #65: not an oversight, but the only safe outcome while the drawing's own
    // Reference is unreachable.
    expect(result.attachmentPathAfterDrawing).toMatch(/^eco-b-.*\.png$/);
  }, 180_000);
});
