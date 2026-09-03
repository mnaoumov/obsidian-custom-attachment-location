import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #72 (G97): `Delete unused attachments in entire vault` judges a
 * designated attachment unit folder as ONE attachment.
 *
 * Two units are staged in the same sweep, because each one alone would pass a test the other fails:
 *
 * - `page_files` is the self-referencing unit the issue is about. A `.excalidraw.md` inside it embeds
 *   its sibling image, and Obsidian really does index that (it is a `.md`), so under the per-file rule
 *   the image carries a backlink forever and the unit is immortal. Only a rule that discounts links
 *   from INSIDE the unit can reach it.
 * - `kept_files` is the other half of the same idea: the note embeds one member, so the whole folder
 *   stays — including a sibling nothing references, which the per-file rule would have trashed. A unit
 *   that travels as one attachment dies as one too.
 *
 * `.excalidraw.md` is load-bearing rather than decorative: `treatAsAttachmentExtensions` keeps
 * `isNoteEx` false for it, so it is an attachment that nonetheless produces real backlinks. A plain
 * `.md` would instead trip the guard that spares any unit holding a real note.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const DELETE_COMMAND_ID = 'obsidian-custom-attachment-location:delete-unused-attachments-entire-vault';
/*
 * Sized the way the sibling entire-vault suite sizes it: the trash step runs on the plugin's internal
 * queue behind whatever else is in flight, and cutting it fine converts a slow-but-correct pass into
 * "the unit folder was never trashed".
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface ProbeResult {
  readonly confirmText: string;
  readonly isKeptOrphanAlive: boolean;
  readonly isKeptUnitAlive: boolean;
  readonly isSelfReferencingImageGone: boolean;
  readonly isSelfReferencingUnitGone: boolean;
  readonly probesFound: boolean;
}

describe('Delete unused attachments in entire vault, attachment unit folders (issue #72)', () => {
  it('trashes a unit nothing outside references, and keeps a referenced one whole', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        deleteCommandId,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        const SETTLE_DELAY_IN_MILLISECONDS = 1000;

        interface UnitFolderSettings {
          attachmentFolderPath: string;
          attachmentUnitFolderPaths: string[];
          isAttachmentUnitFolder(path: string): boolean;
        }

        /*
         * `treatAsAttachmentExtensions` belongs to Advanced Rename and Delete Handler since 12.0.0, and
         * this plugin no longer reads the array — it asks `isTreatedAsAttachment(path)`. Writing the array
         * onto this plugin's settings therefore pins nothing, and would have LOOKED like it worked because
         * the absent-provider default holds `.excalidraw.md` anyway. What this test needs is the
         * PREDICATE's answer, supplied by a stub parked on the read-back component's live ref.
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

        function isUnitFolderSettings(value: unknown): value is UnitFolderSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function'
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
        // Walking the plugin's component tree, keyed off members this plugin still owns.
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

        const EMPTY_RESULT: ProbeResult = {
          confirmText: '',
          isKeptOrphanAlive: false,
          isKeptUnitAlive: false,
          isSelfReferencingImageGone: false,
          isSelfReferencingUnitGone: false,
          probesFound: false
        };

        const foundSettings = findInPluginTree((record) => isUnitFolderSettings(record['settings']) ? record['settings'] : null);
        const foundHolder = findInPluginTree((record) => isHandedOverSettingsHolder(record) ? record : null);
        if (!foundSettings || !foundHolder) {
          return EMPTY_RESULT;
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: UnitFolderSettings = foundSettings;
        const holder: HandedOverSettingsHolder = foundHolder;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorUnitFolderPaths = settings.attachmentUnitFolderPaths;
        const priorApiRef = holder.apiRef;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const noteName = `duf-note-${stamp}`;
        const notePath = `${noteName}.md`;
        const attachmentFolderPath = `duf-assets/${noteName}`;

        const selfReferencingUnitPath = `${attachmentFolderPath}/page_files`;
        const drawingPath = `${selfReferencingUnitPath}/page.excalidraw.md`;
        const selfReferencingImagePath = `${selfReferencingUnitPath}/img.png`;

        const keptUnitPath = `${attachmentFolderPath}/kept_files`;
        const keptImagePath = `${keptUnitPath}/kept-img.png`;
        const keptOrphanPath = `${keptUnitPath}/kept-orphan.png`;

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone: the sweep trashes
         * entries on its own queue, and trashing one a second time throws `ENOENT` from the rename
         * into `.trash`.
         */
        async function trashIfExists(path: string): Promise<void> {
          const existing = app.vault.getAbstractFileByPath(path);
          if (!existing) {
            return;
          }
          try {
            await app.fileManager.trashFile(existing);
          } catch {
            // Removed between the lookup and the trash, which is the outcome this wanted anyway.
          }
        }

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './duf-assets/${noteFileName}';
          settings.attachmentUnitFolderPaths = [selfReferencingUnitPath, keptUnitPath];
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

          await app.vault.createFolder('duf-assets');
          await app.vault.createFolder(attachmentFolderPath);
          await app.vault.createFolder(selfReferencingUnitPath);
          await app.vault.createFolder(keptUnitPath);

          await app.vault.createBinary(selfReferencingImagePath, new ArrayBuffer(4));
          await app.vault.createBinary(keptImagePath, new ArrayBuffer(4));
          await app.vault.createBinary(keptOrphanPath, new ArrayBuffer(4));

          // The drawing embeds its own sibling. That is the unit describing itself, and it is the
          // Backlink that keeps the unit alive forever under the per-file rule.
          await app.vault.create(drawingPath, `![[${selfReferencingImagePath}]]\n`);

          // The note reaches into the OTHER unit only, so `page_files` is referenced by nothing
          // Outside itself while `kept_files` is.
          await app.vault.create(notePath, `![[${keptImagePath}]]\n`);

          await sleep(SETTLE_DELAY_IN_MILLISECONDS);

          await waitUntil({
            message: 'the intra-unit embed was not indexed',
            predicate: () => {
              const imageFile = app.vault.getFileByPath(selfReferencingImagePath);
              return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length > 0;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          await waitUntil({
            message: 'the kept embed was not indexed',
            predicate: () => {
              const keptFile = app.vault.getFileByPath(keptImagePath);
              return keptFile !== null && app.metadataCache.getBacklinksForFile(keptFile).keys().length > 0;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          app.commands.executeCommandById(deleteCommandId);

          await waitUntil({
            message: 'the confirmation dialog never appeared',
            predicate: () => activeDocument.querySelector('.modal-content') !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const confirmText = activeDocument.querySelector('.modal-content')?.textContent ?? '';

          // Confirm through the dialog's own button. Detaching the container would leave the queued
          // Operation's promise unresolved and block everything queued behind it.
          const buttonEls = [...activeDocument.querySelectorAll<HTMLButtonElement>(':scope .modal-content button')];
          const okButtonEl = buttonEls.find((buttonEl) => buttonEl.textContent === 'OK') ?? buttonEls[0];
          okButtonEl?.click();

          await waitUntil({
            message: 'the self-referencing unit folder was never trashed',
            predicate: () => app.vault.getAbstractFileByPath(selfReferencingUnitPath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          return {
            confirmText,
            isKeptOrphanAlive: app.vault.getAbstractFileByPath(keptOrphanPath) !== null,
            isKeptUnitAlive: app.vault.getAbstractFileByPath(keptImagePath) !== null,
            isSelfReferencingImageGone: app.vault.getAbstractFileByPath(selfReferencingImagePath) === null,
            isSelfReferencingUnitGone: app.vault.getAbstractFileByPath(selfReferencingUnitPath) === null,
            probesFound: true
          };
        } finally {
          settings.attachmentFolderPath = priorFolderPath;
          settings.attachmentUnitFolderPaths = priorUnitFolderPaths;
          holder.apiRef = priorApiRef;
          for (
            const path of [
              drawingPath,
              selfReferencingImagePath,
              keptImagePath,
              keptOrphanPath,
              notePath,
              selfReferencingUnitPath,
              keptUnitPath,
              attachmentFolderPath,
              'duf-assets'
            ]
          ) {
            await trashIfExists(path);
          }
        }
      },
      input: {
        deleteCommandId: DELETE_COMMAND_ID,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // The whole folder goes, not file by file.
    expect(result.isSelfReferencingUnitGone).toBe(true);

    /*
     * And the image inside it goes with it. This is the assertion the per-file rule fails: its
     * backlink from the sibling drawing would have kept it, leaving the unit half-deleted forever.
     */
    expect(result.isSelfReferencingImageGone).toBe(true);

    // The referenced unit survives...
    expect(result.isKeptUnitAlive).toBe(true);

    // ...whole, including the member nothing references. A unit dies as one or not at all.
    expect(result.isKeptOrphanAlive).toBe(true);

    // The dialog says plainly that a whole folder goes, and names it.
    expect(result.confirmText).toContain('will be moved to the trash with everything inside them.');
    expect(result.confirmText).toContain('page_files');
    expect(result.confirmText).not.toContain('kept_files');
  }, 180_000);
});
