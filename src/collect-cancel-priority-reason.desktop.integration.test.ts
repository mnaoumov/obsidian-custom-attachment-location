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
  readonly settingsFound: boolean;
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
          return { emptyListReason: '', settingsFound: false, tieReason: '' };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: PrioritySettings = foundSettings;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorPriorities = settings.notePriorities;
        const priorMode = settings.collectAttachmentUsedByMultipleNotesMode;

        async function trashIfExists(path: string): Promise<void> {
          const existing = app.vault.getAbstractFileByPath(path);
          if (existing) {
            await app.fileManager.trashFile(existing);
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
            settings.notePriorities = notePriorities;

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
            app.commands.executeCommandById(collectCommandId);

            await waitUntil({
              message: 'the cancel dialog never explained why the attachment stayed put',
              predicate: () => activeDocument.querySelector(reasonSelector) !== null,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            return activeDocument.querySelector(reasonSelector)?.textContent ?? '';
          } finally {
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
          return { emptyListReason, settingsFound: true, tieReason };
        } finally {
          /* eslint-disable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
          settings.attachmentFolderPath = priorFolderPath;
          settings.notePriorities = priorPriorities;
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

    expect(result.settingsFound).toBe(true);

    // The default: nothing was configured to decide, and the dialog says so rather than leaving the
    // User to guess from a list of notes.
    expect(result.emptyListReason).toBe(
      'It was not moved because the Note priorities setting is empty, so nothing decides which of these notes owns it.'
    );

    // A configured list that cannot separate the notes reads differently, which is the whole point:
    // The two situations need different fixes.
    expect(result.tieReason).toBe(
      'It was not moved because several of these notes match the Note priorities setting equally well, so it names no single owner.'
    );
    expect(result.tieReason).not.toBe(result.emptyListReason);
  }, 180_000);
});
