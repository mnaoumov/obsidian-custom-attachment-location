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
  readonly settingsFound: boolean;
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
          notePriorities: readonly string[];
        }

        function isPrioritySettings(value: unknown): value is PrioritySettings {
          return typeof value === 'object' && value !== null
            && Array.isArray((value as Record<string, unknown>)['notePriorities'])
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        // The plugin does not expose its settings publicly, so locate the live settings object
        // (the one the attachment collector reads) by walking the plugin's component tree.
        function findSettings(): null | PrioritySettings {
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
            if (isPrioritySettings(record['settings'])) {
              return record['settings'];
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

        const foundSettings = findSettings();
        if (!foundSettings) {
          return { drawingStem: '', listedItems: [], plainStems: [], settingsFound: false };
        }
        const settings: PrioritySettings = foundSettings;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorPriorities = settings.notePriorities;
        const priorMode = settings.collectAttachmentUsedByMultipleNotesMode;

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
          settings.notePriorities = ['.md', '.excalidraw.md'];

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
            settingsFound: true
          };
        } finally {
          // The dialog MUST still be dismissed: leaving it open keeps its queue entry pending.
          await closeOpenModals();
          for (const path of [drawingPath, secondPlainPath, firstPlainPath, imagePath]) {
            await trashIfExists(path);
          }
          settings.attachmentFolderPath = priorFolderPath;
          settings.notePriorities = priorPriorities;
          settings.collectAttachmentUsedByMultipleNotesMode = priorMode;
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

    expect(result.settingsFound).toBe(true);

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
