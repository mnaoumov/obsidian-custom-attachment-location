import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #73 (G97): collecting on a note that ALREADY holds a shared
 * attachment, and that outranks the other note referencing it, must move nothing and say nothing.
 * The `multiple notes` box was reporting an ambiguity the priority list had already settled.
 *
 * The staged note embeds two images: one already sitting in the note's own attachment folder and
 * shared with a lower-priority note, and one loose at the vault root that only this note references.
 * The loose image moving is the proof the pass ran to completion - under the reported bug the mode is
 * `Cancel`, so the box would abort the whole run and the loose image would never move at all.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COLLECT_COMMAND_ID = 'obsidian-custom-attachment-location:collect-attachments-in-file';
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface ProbeResult {
  readonly heldImageStillThere: boolean;
  readonly isRenameFlagLive: boolean;
  readonly looseImagePathAfter: null | string;
  readonly probesFound: boolean;
  readonly wasModalOpen: boolean;
}

describe('An unambiguous collect stays quiet when the winning note already holds the attachment (issue #73)', () => {
  it('moves nothing, opens no dialog, and still collects the rest of the note', async () => {
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
          shouldRenameCollectedAttachments: boolean;
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
            && typeof (value as Record<string, unknown>)['shouldRenameCollectedAttachments'] === 'boolean';
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
          return { heldImageStillThere: false, isRenameFlagLive: false, looseImagePathAfter: null, probesFound: false, wasModalOpen: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: PrioritySettings = foundSettings;
        const holder: HandedOverSettingsHolder = foundHolder;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorApiRef = holder.apiRef;
        const priorMode = settings.collectAttachmentUsedByMultipleNotesMode;
        const wasRenamingCollectedAttachments = settings.shouldRenameCollectedAttachments;

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
         * Dismiss through the dialog's own button, never by detaching `.modal-container`. Detaching
         * leaves the modal's promise unresolved, so the queued collect operation never finishes and
         * the NEXT collect command silently waits behind it in the queue forever.
         */
        async function closeOpenModals(): Promise<void> {
          if (activeDocument.querySelector('.modal-container') === null) {
            return;
          }
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
        const firstNotePath = `wh-first-${stamp}.md`;
        const secondNotePath = `wh-second-${stamp}.md`;
        const attachmentFolderPath = `assets/wh-first-${stamp}`;
        const heldImagePath = `${attachmentFolderPath}/wh-held-${stamp}.png`;
        const looseImagePath = `wh-loose-${stamp}.png`;
        const collectedLooseImagePath = `${attachmentFolderPath}/wh-loose-${stamp}.png`;

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './assets/${noteFileName}';
          settings.collectAttachmentUsedByMultipleNotesMode = 'Cancel';
          // The names must survive the collect, or `already in place` would never be true.
          settings.shouldRenameCollectedAttachments = false;
          // The collected note outranks the other one, so it owns the shared image outright.
          stubProvider([firstNotePath, secondNotePath]);

          await app.vault.createFolder(attachmentFolderPath);
          await app.vault.createBinary(heldImagePath, new ArrayBuffer(4));
          await app.vault.createBinary(looseImagePath, new ArrayBuffer(4));
          const firstNote = await app.vault.create(firstNotePath, `![[${heldImagePath}]]\n\n![[${looseImagePath}]]\n`);
          await app.vault.create(secondNotePath, `![[${heldImagePath}]]\n`);

          // Both embeds of the held image must be indexed, or the collector sees one referencing note
          // And the multiple-notes path never runs at all.
          await waitUntil({
            message: 'both embeds of the held image were not indexed',
            predicate: () => {
              const heldImageFile = app.vault.getFileByPath(heldImagePath);
              return heldImageFile !== null && app.metadataCache.getBacklinksForFile(heldImageFile).keys().length >= 2;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          await app.workspace.getLeaf(false).openFile(firstNote);

          /*
           * The collect command reads the ACTIVE file, and `openFile` resolves before the workspace
           * Has finished switching to it. Firing the command too early collects nothing at all, which
           * Would make this test pass for entirely the wrong reason.
           */
          await waitUntil({
            message: 'the staged note never became the active file',
            predicate: () => app.workspace.getActiveFile()?.path === firstNote.path,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          app.commands.executeCommandById(collectCommandId);

          /*
           * The loose image landing in the note's attachment folder is the completion signal. Under
           * The reported bug the `Cancel` box fires on the held image first and aborts the run, so
           * This wait is what fails - and it fails saying the pass never got that far.
           */
          await waitUntil({
            message: 'the loose image never reached the attachment folder, so the collect pass did not run to completion',
            predicate: () => app.vault.getFileByPath(collectedLooseImagePath) !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          return {
            heldImageStillThere: app.vault.getFileByPath(heldImagePath) !== null,
            isRenameFlagLive: typeof settings.shouldRenameCollectedAttachments === 'boolean',
            looseImagePathAfter: app.vault.getFileByPath(collectedLooseImagePath)?.path ?? null,
            probesFound: true,
            wasModalOpen: activeDocument.querySelector('.modal-container') !== null
          };
        } finally {
          // A dialog MUST still be dismissed: leaving it open keeps its queue entry pending.
          await closeOpenModals();
          for (const path of [secondNotePath, firstNotePath, collectedLooseImagePath, looseImagePath, heldImagePath, attachmentFolderPath]) {
            await trashIfExists(path);
          }
          // Restoring the values captured before the awaits; nothing else in this vault writes them.
          settings.attachmentFolderPath = priorFolderPath;
          holder.apiRef = priorApiRef;
          settings.collectAttachmentUsedByMultipleNotesMode = priorMode;
          settings.shouldRenameCollectedAttachments = wasRenamingCollectedAttachments;
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
    expect(result.isRenameFlagLive).toBe(true);

    // The shared image the winning note already held never moved, and nothing was said about it.
    expect(result.heldImageStillThere).toBe(true);
    expect(result.wasModalOpen).toBe(false);

    // And the rest of the note was still collected, so the quiet is a settled collect rather than a
    // Pass that gave up early.
    expect(result.looseImagePathAfter).not.toBeNull();
  }, 180_000);
});
