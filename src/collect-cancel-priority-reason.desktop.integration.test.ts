import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #66 (G97): the dialog that appears when collecting cancels on a
 * shared attachment must say WHY the attachment stayed put, not merely that several notes reference
 * it. The reporter's words were "allows user to identify the real reason an image is not moving".
 *
 * Two of the three reasons are staged for real, because they are the two a user can actually cause:
 * an empty priority list (the default), and a tie between notes that match it equally well. The
 * third, "nothing matched", differs only in which string is picked and is covered by the unit tests.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COLLECT_COMMAND_ID = 'obsidian-custom-attachment-location:collect-attachments-in-file';
const REASON_SELECTOR = '.custom-attachment-location-no-priority-winner-reason';
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface ProbeResult {
  readonly emptyListReason: string;
  readonly probesFound: boolean;
  readonly tieReason: string;
}

describe('The cancel dialog names the real reason a shared attachment did not move (issue #66)', () => {
  it('reports an empty priority list and a tie as distinct reasons', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        collectCommandId,
        lib: { waitUntil },
        pluginId,
        reasonSelector,
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

        const foundSettings = findInPluginTree((record) => isPrioritySettings(record['settings']) ? record['settings'] : null);
        const foundHolder = findInPluginTree((record) => isHandedOverSettingsHolder(record) ? record : null);
        if (!foundSettings || !foundHolder) {
          return { emptyListReason: '', probesFound: false, tieReason: '' };
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

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone: the collect pass
         * moves and removes entries on its own queue, and trashing one a second time throws `ENOENT`
         * from the rename into `.trash`.
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

        /*
         * Dismiss through the dialog's own Cancel button, never by detaching `.modal-container`.
         * Detaching leaves the modal's promise unresolved, so the queued collect operation never
         * finishes and the NEXT collect command silently waits behind it in the queue forever.
         */
        async function closeOpenModals(): Promise<void> {
          for (const buttonEl of activeDocument.querySelectorAll<HTMLButtonElement>(':scope .modal-content button')) {
            buttonEl.click();
          }
          await waitUntil({
            message: 'the dialog stayed open after its button was clicked',
            predicate: () => activeDocument.querySelector('.modal-container') === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
        }

        /*
         * Stages one image embedded by two plain markdown notes, runs the collect command, and reads
         * the explanation off the dialog the plugin opens.
         */
        async function readReason(notePriorities: readonly string[]): Promise<string> {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const imagePath = `cr-img-${stamp}.png`;
          const firstNotePath = `cr-first-${stamp}.md`;
          const secondNotePath = `cr-second-${stamp}.md`;

          try {
            stubProvider(notePriorities);

            await app.vault.createBinary(imagePath, new ArrayBuffer(4));
            const firstNote = await app.vault.create(firstNotePath, `![[${imagePath}]]\n`);
            await app.vault.create(secondNotePath, `![[${imagePath}]]\n`);

            // Both embeds must be indexed, or the collector sees one referencing note and the
            // Multiple-notes path never runs at all.
            await waitUntil({
              message: 'both embeds were not indexed',
              predicate: () => {
                const imageFile = app.vault.getFileByPath(imagePath);
                return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length >= 2;
              },
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            await app.workspace.getLeaf(false).openFile(firstNote);

            /*
             * The collect command reads the ACTIVE file, and `openFile` resolves before the workspace
             * Has finished switching to it. Firing the command too early collects nothing, opens no
             * Dialog, and surfaces 20s later as "the cancel dialog never explained why" — a message
             * About the dialog's content when the dialog was never asked for in the first place.
             */
            await waitUntil({
              message: 'the staged note never became the active file',
              predicate: () => app.workspace.getActiveFile()?.path === firstNote.path,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            app.commands.executeCommandById(collectCommandId);

            await waitUntil({
              message: 'the cancel dialog never explained why the attachment stayed put',
              predicate: () => activeDocument.querySelector(reasonSelector) !== null,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            return activeDocument.querySelector(reasonSelector)?.textContent ?? '';
          } finally {
            // The dialog MUST still be dismissed: leaving it open keeps its queue entry pending.
            await closeOpenModals();
            for (const path of [secondNotePath, firstNotePath, imagePath]) {
              await trashIfExists(path);
            }
          }
        }

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './assets/${noteFileName}';
          settings.collectAttachmentUsedByMultipleNotesMode = 'Cancel';

          const emptyListReason = await readReason([]);
          // Both notes are plain `.md`, so the one entry matches them equally well: a tie.
          const tieReason = await readReason(['.md']);
          return { emptyListReason, probesFound: true, tieReason };
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
        reasonSelector: REASON_SELECTOR,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // The default: nothing was configured to decide, and the dialog says so rather than leaving the
    // User to guess from a list of notes. Since 12.0.0 the setting name is qualified by the plugin
    // That owns it, because that is where the user has to go to change it.
    expect(result.emptyListReason).toBe(
      'It was not moved because the Advanced Rename and Delete Handler → Note priorities setting is empty, so nothing decides which of these notes owns it.'
    );

    // A configured list that cannot separate the notes reads differently, which is the whole point:
    // The two situations need different fixes.
    expect(result.tieReason).toBe(
      'It was not moved because several of these notes match the Advanced Rename and Delete Handler → Note priorities setting equally well, so it names no single owner.'
    );
    expect(result.tieReason).not.toBe(result.emptyListReason);
  }, 180_000);
});
