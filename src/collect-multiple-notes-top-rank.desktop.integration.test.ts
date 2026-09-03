import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #74 (G97): the dialog that appears when collecting cannot decide which
 * note owns a shared attachment must list only the notes tying for the HIGHEST rank. A note the
 * priority list deliberately ranked below them cannot resolve the ambiguity, so listing it is noise -
 * the reporter's words were "allows user to only see the relevant notes to solve the ambiguity".
 *
 * The reporter's shape is staged for real: a note that ends in `.md` but is demoted by a longer entry,
 * beside two plain notes that tie. Longest-match is what does the demoting, so this also proves the
 * rank comes from the configured list rather than from the file extension.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COLLECT_COMMAND_ID = 'obsidian-custom-attachment-location:collect-attachments-in-file';
const LIST_ITEM_SELECTOR = '.custom-attachment-location-multiple-notes-list li';
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface ProbeResult {
  readonly drawingStem: string;
  readonly listedItems: readonly string[];
  readonly plainStems: readonly string[];
  readonly probesFound: boolean;
}

describe('The shared-attachment dialog lists only the top-ranked notes (issue #74)', () => {
  it('omits a note the priority list ranked below the tied ones', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        collectCommandId,
        lib: { waitUntil },
        listItemSelector,
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface PrioritySettings {
          attachmentFolderPath: string;
          collectAttachmentUsedByMultipleNotesMode: string;
        }

        /*
         * `notePriorities` belongs to Advanced Rename and Delete Handler since 12.0.0, and this plugin
         * reads it back through that plugin's API. So the ranking is no longer writable here - the
         * PROVIDER is what this stubs, by parking one on the read-back component's live ref. That
         * exercises the real read path (`apiRef.value.getSettings()`) without needing the other plugin
         * installed in the vault.
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
          return { drawingStem: '', listedItems: [], plainStems: [], probesFound: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: PrioritySettings = foundSettings;
        const holder: HandedOverSettingsHolder = foundHolder;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorApiRef = holder.apiRef;
        const priorMode = settings.collectAttachmentUsedByMultipleNotesMode;

        // Mirrors this plugin's own absent-provider defaults, so only the ranking under test differs
        // From what a vault with no provider would see.
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

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const imagePath = `tr-img-${stamp}.png`;
        const firstPlainStem = `tr-plain-a-${stamp}`;
        const secondPlainStem = `tr-plain-b-${stamp}`;
        const drawingStem = `tr-drawing-${stamp}`;
        const firstPlainPath = `${firstPlainStem}.md`;
        const secondPlainPath = `${secondPlainStem}.md`;
        const drawingPath = `${drawingStem}.excalidraw.md`;

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './assets/${noteFileName}';
          settings.collectAttachmentUsedByMultipleNotesMode = 'Cancel';
          /*
           * Longest-match ranks `*.excalidraw.md` below a plain `.md`, even though it ends with `.md`
           * too. That is the override the reporter configured, and the whole point of the case.
           */
          stubProvider(['.md', '.excalidraw.md']);

          await app.vault.createBinary(imagePath, new ArrayBuffer(4));
          const firstPlainNote = await app.vault.create(firstPlainPath, `![[${imagePath}]]\n`);
          await app.vault.create(secondPlainPath, `![[${imagePath}]]\n`);
          await app.vault.create(drawingPath, `![[${imagePath}]]\n`);

          // All three embeds must be indexed, or the collector sees fewer referencing notes and the
          // Tie this test is about never forms.
          await waitUntil({
            message: 'the three embeds were not indexed',
            predicate: () => {
              const imageFile = app.vault.getFileByPath(imagePath);
              return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length >= 3;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          await app.workspace.getLeaf(false).openFile(firstPlainNote);

          /*
           * The collect command reads the ACTIVE file, and `openFile` resolves before the workspace
           * Has finished switching to it. Firing the command too early collects nothing and opens no
           * Dialog, which surfaces 20s later as a message about a dialog that was never asked for.
           */
          await waitUntil({
            message: 'the staged note never became the active file',
            predicate: () => app.workspace.getActiveFile()?.path === firstPlainNote.path,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          app.commands.executeCommandById(collectCommandId);

          await waitUntil({
            message: 'the cancel dialog never listed the notes sharing the attachment',
            predicate: () => activeDocument.querySelectorAll(listItemSelector).length > 0,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const listedItems = [...activeDocument.querySelectorAll(listItemSelector)].map((itemEl) => itemEl.textContent);
          return {
            drawingStem,
            listedItems,
            plainStems: [firstPlainStem, secondPlainStem],
            probesFound: true
          };
        } finally {
          // The dialog MUST still be dismissed: leaving it open keeps its queue entry pending.
          await closeOpenModals();
          for (const path of [drawingPath, secondPlainPath, firstPlainPath, imagePath]) {
            await trashIfExists(path);
          }
          /* eslint-disable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
          settings.attachmentFolderPath = priorFolderPath;
          holder.apiRef = priorApiRef;
          settings.collectAttachmentUsedByMultipleNotesMode = priorMode;
          /* eslint-enable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
        }
      },
      input: {
        collectCommandId: COLLECT_COMMAND_ID,
        listItemSelector: LIST_ITEM_SELECTOR,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // Exactly the two notes that tie for the best rank - the demoted one is not one of them.
    expect(result.listedItems).toHaveLength(2);

    const listedText = result.listedItems.join('\n');
    for (const plainStem of result.plainStems) {
      expect(listedText).toContain(plainStem);
    }

    // The regression: before the fix this note appeared alongside the two it cannot arbitrate between.
    expect(listedText).not.toContain(result.drawingStem);
  }, 180_000);
});
