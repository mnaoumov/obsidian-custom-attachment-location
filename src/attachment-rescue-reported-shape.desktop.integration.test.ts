import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * Issue #67 reported that deleting a folder does not hand its still-referenced attachment to the
 * surviving note. Read against the reporter's own sample vault, the report is a configuration
 * question rather than a defect: their `data.json` has BOTH gates off
 * (`shouldRescueSharedAttachments: false`, `shouldDeleteOrphanAttachments: false`), so the rescue was
 * never armed.
 *
 * `attachment-rescue.desktop.integration.test.ts` already covers folder deletion, but the reported
 * vault differs from it in two ways that could each plausibly have been the real defect, so both are
 * pinned here rather than assumed harmless:
 *
 *   - the attachment sits in a SUBFOLDER of the deleted folder (`A/attachments/`), not beside the note;
 *   - both notes reference it by FULL PATH (`![[A/attachments/Nature.png]]`), not by a short link.
 *
 * The control phase reproduces exactly what the reporter saw, so the two phases together are the
 * answer to the issue: same vault, same steps, one setting apart.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface PhaseResult {
  readonly isAttachmentInSurvivingNoteFolder: boolean;
  readonly survivingAttachmentPath: string;
}

interface ProbeResult {
  readonly rescueOff: PhaseResult;
  readonly rescueOn: PhaseResult;
  readonly settingsFound: boolean;
}

describe('Deleting a folder hands its shared attachment to the surviving note (issue #67)', () => {
  it('rescues the attachment once the setting is on, and reproduces the report while it is off', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface RescueSettings {
          attachmentFolderPath: string;
          notePriorities: readonly string[];
          shouldDeleteOrphanAttachments: boolean;
          shouldRescueSharedAttachments: boolean;
        }

        function isRescueSettings(value: unknown): value is RescueSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldRescueSharedAttachments'] === 'boolean'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        // The plugin does not expose its settings publicly, so locate the live settings object by
        // Walking the plugin's component tree.
        function findSettings(): null | RescueSettings {
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
            if (isRescueSettings(record['settings'])) {
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

        const EMPTY_PHASE: PhaseResult = { isAttachmentInSurvivingNoteFolder: false, survivingAttachmentPath: '' };

        const foundSettings = findSettings();
        if (!foundSettings) {
          return { rescueOff: EMPTY_PHASE, rescueOn: EMPTY_PHASE, settingsFound: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: RescueSettings = foundSettings;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorPriorities = settings.notePriorities;
        const wasDeletingOrphans = settings.shouldDeleteOrphanAttachments;
        const wasRescuingShared = settings.shouldRescueSharedAttachments;

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone. `folderA` is trashed
         * by the phase itself and the index can still hand it back here for a moment afterwards, and
         * the rescue removes emptied folders on its own queue — trashing either one a second time
         * throws `ENOENT` from the rename into `.trash` and fails the phase that already passed.
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
         * Stages the reporter's vault: `A/Note A.md` plus `A/attachments/img.png`, and `B/Note B.md`
         * embedding that same image by full path. Then deletes `A/`.
         */
        async function runPhase(shouldRescue: boolean): Promise<PhaseResult> {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const folderA = `ars-a-${stamp}`;
          const folderB = `ars-b-${stamp}`;
          const imagePath = `${folderA}/attachments/ars-img-${stamp}.png`;
          const noteAPath = `${folderA}/Note A.md`;
          const noteBPath = `${folderB}/Note B.md`;

          try {
            settings.shouldRescueSharedAttachments = shouldRescue;

            await app.vault.createFolder(folderA);
            await app.vault.createFolder(`${folderA}/attachments`);
            await app.vault.createFolder(folderB);
            await app.vault.createBinary(imagePath, new ArrayBuffer(4));
            await app.vault.create(noteAPath, `![[${imagePath}]]\n`);
            await app.vault.create(noteBPath, `![[${imagePath}]]\n`);

            // Both embeds must be indexed, or the deletion sees no surviving reference at all.
            await waitUntil({
              message: 'both embeds were not indexed',
              predicate: () => {
                const imageFile = app.vault.getFileByPath(imagePath);
                return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length >= 2;
              },
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            const folderAFile = app.vault.getAbstractFileByPath(folderA);
            if (folderAFile) {
              await app.fileManager.trashFile(folderAFile);
            }

            const expectedPath = `${folderB}/attachments/ars-img-${stamp}.png`;
            let isRescued = false;
            const deadline = Date.now() + waitTimeoutInMilliseconds;
            while (Date.now() < deadline) {
              if (app.vault.getAbstractFileByPath(expectedPath)) {
                isRescued = true;
                break;
              }
              await sleep(300);
            }

            const surviving = app.vault.getFiles().map((file) => file.path).find((path) => path.includes(`ars-img-${stamp}`)) ?? '';
            return { isAttachmentInSurvivingNoteFolder: isRescued, survivingAttachmentPath: surviving };
          } finally {
            for (const path of [noteBPath, folderB, folderA]) {
              await trashIfExists(path);
            }
          }
        }

        try {
          settings.attachmentFolderPath = './attachments';
          settings.notePriorities = ['.md', 'property:excalidraw-plugin'];
          settings.shouldDeleteOrphanAttachments = true;

          const rescueOff = await runPhase(false);
          const rescueOn = await runPhase(true);
          return { rescueOff, rescueOn, settingsFound: true };
        } finally {
          /* eslint-disable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
          settings.attachmentFolderPath = priorFolderPath;
          settings.notePriorities = priorPriorities;
          settings.shouldDeleteOrphanAttachments = wasDeletingOrphans;
          settings.shouldRescueSharedAttachments = wasRescuingShared;
          /* eslint-enable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
        }
      },
      input: {
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // The report, reproduced: with the rescue off the image goes down with the folder.
    expect(result.rescueOff.isAttachmentInSurvivingNoteFolder).toBe(false);

    // With it on, the reported shape works — a subfolder of the deleted folder and full-path
    // Wikilinks included, which is what this test exists to prove.
    expect(result.rescueOn.isAttachmentInSurvivingNoteFolder).toBe(true);
    expect(result.rescueOn.survivingAttachmentPath).toMatch(/^ars-b-.*\/attachments\/ars-img-.*\.png$/);
  }, 180_000);
});
