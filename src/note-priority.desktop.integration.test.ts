import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #57 (G97): `notePriorities` decides which of several referencing
 * notes owns an attachment, so collecting no longer has to fall back to
 * `collectAttachmentUsedByMultipleNotesMode`.
 *
 * The reporter's scenario, staged literally: one image embedded by BOTH a plain markdown note and an
 * Excalidraw note. The control phase proves the attachment is left where it is without the setting —
 * which is the behavior being replaced — and the fix phase proves it lands in the higher-priority
 * note's folder.
 *
 * Note the fix phase deliberately runs the command on the LOSING note: priority decides ownership,
 * not whichever note you happened to have open. That is the behavior worth pinning down, because it
 * is the surprising half of the feature.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COLLECT_COMMAND_ID = 'obsidian-custom-attachment-location:collect-attachments-in-file';
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface PhaseResult {
  readonly attachmentPath: string;
  readonly movedIntoWinnerFolder: boolean;
}

interface ProbeResult {
  readonly control: PhaseResult;
  readonly fix: PhaseResult;
  readonly probesFound: boolean;
}

describe('Note priorities decide which note owns a shared attachment (issue #57)', () => {
  it('moves the attachment into the highest-priority referencing note, even when collecting the other one', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        collectCommandId,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface PrioritySettings {
          attachmentFolderPath: string;
          collectAttachmentUsedByMultipleNotesMode: string;
        }

        /*
         * `notePriorities` belongs to Advanced Rename and Delete Handler since 12.0.0, and this plugin
         * reads it back through that plugin's API. So the setting is no longer writable here — the
         * PROVIDER is what the phases swap, by parking a stub on the read-back component's live ref.
         * That exercises the real read path (`apiRef.value.getSettings()`) without needing the other
         * plugin installed in the vault.
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

        function isPrioritySettings(value: unknown): value is PrioritySettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string'
            && typeof (value as Record<string, unknown>)['collectAttachmentUsedByMultipleNotesMode'] === 'string';
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

        const EMPTY_PHASE: PhaseResult = { attachmentPath: '', movedIntoWinnerFolder: false };

        const foundSettings = findInPluginTree((record) => isPrioritySettings(record['settings']) ? record['settings'] : null);
        const foundHolder = findInPluginTree((record) => isHandedOverSettingsHolder(record) ? record : null);
        if (!foundSettings || !foundHolder) {
          return { control: EMPTY_PHASE, fix: EMPTY_PHASE, probesFound: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: PrioritySettings = foundSettings;
        const holder: HandedOverSettingsHolder = foundHolder;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorApiRef = holder.apiRef;
        const priorMode = settings.collectAttachmentUsedByMultipleNotesMode;

        // Mirrors this plugin's own absent-provider defaults, so only the value under test differs
        // Between the two phases.
        function stubProvider(notePriorities: readonly string[]): void {
          holder.apiRef = {
            value: {
              getSettings: (): Record<string, unknown> => ({
                emptyFolderBehavior: 'DeleteWithEmptyParents',
                notePriorities,
                shouldRenameAttachmentFiles: false,
                treatAsAttachmentExtensions: ['.excalidraw.md']
              }),
              isPathIgnored: (): boolean => false,
              isTreatedAsAttachment: (path: string): boolean => path.endsWith('.excalidraw.md')
            }
          };
        }

        async function trashIfExists(path: string): Promise<void> {
          const existing = app.vault.getAbstractFileByPath(path);
          if (existing) {
            await app.fileManager.trashFile(existing);
          }
        }

        /*
         * Stages one image embedded by two notes: a plain markdown one and an Excalidraw one. Both
         * are `.md` files on disk, which is exactly why the priority entries have to distinguish them
         * by the longest match rather than by a bare suffix.
         */
        async function runPhase(notePriorities: readonly string[]): Promise<PhaseResult> {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const imagePath = `np-img-${stamp}.png`;
          const plainNotePath = `np-note-${stamp}.md`;
          const drawingNotePath = `np-drawing-${stamp}.excalidraw.md`;
          const createdPaths = [imagePath, plainNotePath, drawingNotePath];

          try {
            stubProvider(notePriorities);

            await app.vault.createBinary(imagePath, new ArrayBuffer(4));
            const plainNote = await app.vault.create(plainNotePath, `![[${imagePath}]]\n`);
            const drawingNote = await app.vault.create(drawingNotePath, `![[${imagePath}]]\n`);

            // Both embeds must be indexed, or the collector sees only one referencing note and the
            // Multiple-notes path never runs at all.
            await waitUntil({
              message: 'both embeds were not indexed',
              predicate: () => {
                const imageFile = app.vault.getFileByPath(imagePath);
                return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length >= 2;
              },
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            // Run the command on the DRAWING. With `.md` ranked above `.excalidraw.md` the image is
            // Still handed to the plain note, which is the surprising half of the feature.
            await app.workspace.getLeaf(false).openFile(drawingNote);
            app.commands.executeCommandById(collectCommandId);

            const winnerFolder = `assets/np-note-${stamp}`;
            const expectedPath = `${winnerFolder}/np-img-${stamp}.png`;

            // Either it lands in the winner's folder, or nothing happens at all. Poll for the former
            // And let the timeout report the latter.
            let isMoved = false;
            const deadline = Date.now() + waitTimeoutInMilliseconds;
            while (Date.now() < deadline) {
              if (app.vault.getAbstractFileByPath(expectedPath)) {
                isMoved = true;
                break;
              }
              await sleep(300);
            }

            const remaining = app.vault.getFiles().map((file) => file.path).find((path) => path.includes(`np-img-${stamp}`)) ?? '';
            createdPaths.push(remaining, plainNote.path);
            return { attachmentPath: remaining, movedIntoWinnerFolder: isMoved };
          } finally {
            for (const path of createdPaths.filter(Boolean).reverse()) {
              await trashIfExists(path);
            }
            await trashIfExists(`assets/np-note-${stamp}`);
            await trashIfExists(`assets/np-drawing-${stamp}`);
          }
        }

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './assets/${noteFileName}';
          settings.collectAttachmentUsedByMultipleNotesMode = 'Skip';

          const control = await runPhase([]);
          const fix = await runPhase(['.md', '.excalidraw.md']);
          return { control, fix, probesFound: true };
        } finally {
          /* eslint-disable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
          settings.attachmentFolderPath = priorFolderPath;
          holder.apiRef = priorApiRef;
          settings.collectAttachmentUsedByMultipleNotesMode = priorMode;
          /* eslint-enable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
        }
      },
      input: {
        collectCommandId: COLLECT_COMMAND_ID,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // Control: with no priority configured the shared attachment is left alone (Skip mode).
    expect(result.control.movedIntoWinnerFolder).toBe(false);
    expect(result.control.attachmentPath).toMatch(/^np-img-.*\.png$/);

    // Fix: the plain markdown note outranks the Excalidraw one and takes the image, even though the
    // Command was run on the drawing.
    expect(result.fix.movedIntoWinnerFolder).toBe(true);
    expect(result.fix.attachmentPath).toMatch(/^assets\/np-note-.*\/np-img-.*\.png$/);
  }, 180_000);
});
