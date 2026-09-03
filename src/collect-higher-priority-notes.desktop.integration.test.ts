import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #75 (G97): collecting from a note the priority list ranks BELOW the
 * others hands the attachment away to the winner, and used to do it in silence. The reporter asked to
 * "see the notes of higher priority that are referencing the image", so a notice must name them.
 *
 * The reporter's shape is staged for real: an image embedded in a drawing and in a plain note, with
 * the plain note ranked above it. The command runs on the DRAWING - the outranked note - which is the
 * only case that reports. Running it on the winner stays silent, which is issue #73's rule.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COLLECT_COMMAND_ID = 'obsidian-custom-attachment-location:collect-attachments-in-file';
const LIST_ITEM_SELECTOR = '.custom-attachment-location-higher-priority-notes-list li';
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface ProbeResult {
  readonly drawingStem: string;
  readonly listedItems: readonly string[];
  readonly plainStem: string;
  readonly settingsFound: boolean;
}

describe('Collecting from an outranked note names the higher-priority notes (issue #75)', () => {
  it('reports the note that really owns the attachment', async () => {
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
          return { drawingStem: '', listedItems: [], plainStem: '', settingsFound: false };
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
         * The report is a notice, not a modal, so nothing is waiting on it and detaching it cannot
         * strand a queue entry. It is shown with an infinite duration on purpose - its links are meant
         * to be clicked - so it has to be taken off the screen rather than waited out.
         */
        function removeOpenNotices(): void {
          for (const noticeEl of activeDocument.querySelectorAll('.notice')) {
            noticeEl.remove();
          }
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const imagePath = `hp-img-${stamp}.png`;
        const plainStem = `hp-plain-${stamp}`;
        const drawingStem = `hp-drawing-${stamp}`;
        const plainPath = `${plainStem}.md`;
        const drawingPath = `${drawingStem}.excalidraw.md`;

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './assets/${noteFileName}';
          // Never reached on the winner path; set to the quietest mode so a regression fails on the
          // Missing notice rather than hanging on a dialog.
          settings.collectAttachmentUsedByMultipleNotesMode = 'Skip';
          /*
           * Longest-match ranks `*.excalidraw.md` below a plain `.md`, even though it ends with `.md`
           * too, so the drawing the command runs on is the outranked note.
           */
          settings.notePriorities = ['.md', '.excalidraw.md'];

          await app.vault.createBinary(imagePath, new ArrayBuffer(4));
          await app.vault.create(plainPath, `![[${imagePath}]]\n`);
          const drawingNote = await app.vault.create(drawingPath, `![[${imagePath}]]\n`);

          // Both embeds must be indexed, or the collector sees a single referencing note and the
          // Priority list is never consulted at all.
          await waitUntil({
            message: 'the two embeds were not indexed',
            predicate: () => {
              const imageFile = app.vault.getFileByPath(imagePath);
              return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length >= 2;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          await app.workspace.getLeaf(false).openFile(drawingNote);

          /*
           * The collect command reads the ACTIVE file, and `openFile` resolves before the workspace
           * Has finished switching to it. Firing the command too early collects nothing and shows no
           * Notice, which surfaces 20s later as a message about a report that was never asked for.
           */
          await waitUntil({
            message: 'the staged drawing never became the active file',
            predicate: () => app.workspace.getActiveFile()?.path === drawingNote.path,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          app.commands.executeCommandById(collectCommandId);

          await waitUntil({
            message: 'no notice named the notes ranked above the collected one',
            predicate: () => activeDocument.querySelectorAll(listItemSelector).length > 0,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const listedItems = [...activeDocument.querySelectorAll(listItemSelector)].map((itemEl) => itemEl.textContent);
          return {
            drawingStem,
            listedItems,
            plainStem,
            settingsFound: true
          };
        } finally {
          removeOpenNotices();
          for (const path of [drawingPath, plainPath, imagePath, `assets/${plainStem}`, `assets/${drawingStem}`]) {
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

    // Exactly the one note that outranks the drawing the command ran on.
    expect(result.listedItems).toHaveLength(1);

    const listedText = result.listedItems.join('\n');

    // The regression: before the fix the collect moved the image to this note without saying so.
    expect(listedText).toContain(result.plainStem);

    // The collected note is not "higher priority than itself", so it is never on its own report.
    expect(listedText).not.toContain(result.drawingStem);
  }, 180_000);
});
