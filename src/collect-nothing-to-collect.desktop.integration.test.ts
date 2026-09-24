import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for issue #81: `Collect attachments in current note` must say so when it moves
 * nothing, instead of leaving the user looking at a command that did nothing at all.
 *
 * The reporter's shape is staged for real: an attachment already sitting in the folder the note's own
 * template resolves to, so every destination the collect computes is the path the file already has
 * and the whole run is a correct no-op. Before the fix that outcome reached the console alone, and the
 * reporter read the command as inert and filed a bug against it.
 *
 * Two phases over the same shape, because the notice has two halves:
 *   - hint -> renaming collected attachments is ON while the template that would give them a new name
 *     is EMPTY, which is the reporter's own configuration and the one that makes the outcome
 *     inevitable; the notice names that setting;
 *   - plain -> renaming is OFF, so nothing is contradicting itself and the notice is the first half
 *     alone.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const ATTACHMENT_FOLDER_PATH = '_Attachments';
const NOTHING_TO_COLLECT_PREFIX = 'Nothing to collect in';
const COLLECTED_FILE_NAME_SETTING = 'Collected attachment file name';
/*
 * Under the transport's ~30s per-closure cap, not at it.
 * The closure spends this ceiling twice per phase and runs two phases, so at 10_000 it declared 40s.
 * The eval is killed at the cap first and reported as a bare transport timeout.
 * That names the harness rather than the wait that overran.
 * Each step is a vault write or a queued collect in a small temp vault, well under a second.
 * The constant feeds nothing but closure input, so no Node-side wait sees the change.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 5000;

interface PhaseResult {
  readonly attachmentStillInPlace: boolean;
  readonly noteStem: string;
  readonly noticeText: string;
}

interface ProbeResult {
  readonly hint: PhaseResult;
  readonly plain: PhaseResult;
  readonly probesFound: boolean;
}

describe('A collect that moves nothing says so (issue #81)', () => {
  it('reports the run, and names the setting that pinned every attachment where it was', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        attachmentFolderPath,
        findPluginSettingsComponent: findSettingsComponent,
        lib: { waitUntil },
        nothingToCollectPrefix,
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface NothingToCollectSettings {
          attachmentFolderPath: string;
          collectedAttachmentFileName: string;
          collectedAttachmentFolderPath: string;
          shouldRenameCollectedAttachments: boolean;
        }

        type CollectAttachmentsInAbstractFilesFunction = (this: unknown, abstractFiles: unknown[]) => void;

        function isNothingToCollectSettings(value: unknown): value is NothingToCollectSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['collectedAttachmentFileName'] === 'string'
            && typeof record['collectedAttachmentFolderPath'] === 'string'
            && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
        }

        const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;

        const foundSettingsComponent = findSettingsComponent(pluginRecord, isNothingToCollectSettings);
        const foundCollect = pluginRecord?.['collectAttachmentsInAbstractFiles'];
        if (!foundSettingsComponent || typeof foundCollect !== 'function') {
          const emptyPhase: PhaseResult = { attachmentStillInPlace: false, noteStem: '', noticeText: '' };
          return { hint: emptyPhase, plain: emptyPhase, probesFound: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settingsComponent = foundSettingsComponent;
        const collectAttachmentsInAbstractFiles = foundCollect as CollectAttachmentsInAbstractFilesFunction;

        const priorFolderPath = settingsComponent.settings.attachmentFolderPath;
        const priorCollectedFolderPath = settingsComponent.settings.collectedAttachmentFolderPath;
        const priorCollectedFileName = settingsComponent.settings.collectedAttachmentFileName;
        const wasRenamingCollectedAttachments = settingsComponent.settings.shouldRenameCollectedAttachments;

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
         * strand a queue entry. It is shown with an infinite duration on purpose - a message about an
         * absence of change is worth more than a few seconds - so it has to be taken off the screen
         * rather than waited out, and the second phase would otherwise read the first phase's notice.
         */
        function removeOpenNotices(): void {
          for (const noticeEl of activeDocument.querySelectorAll('.notice')) {
            noticeEl.remove();
          }
        }

        function findNothingToCollectNotice(): null | string {
          for (const noticeEl of activeDocument.querySelectorAll('.notice')) {
            const text = noticeEl.textContent;
            if (text.includes(nothingToCollectPrefix)) {
              return text;
            }
          }
          return null;
        }

        async function runPhase(shouldRenameCollectedAttachments: boolean, label: string): Promise<PhaseResult> {
          await settingsComponent.editAndSave((settings) => {
            settings.shouldRenameCollectedAttachments = shouldRenameCollectedAttachments;
          });

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const noteStem = `ntc-${label}-${stamp}`;
          const notePath = `${noteStem}.md`;
          const imageFileName = `ntc-img-${label}-${stamp}.png`;
          // Already sitting where this note's template resolves to, which is the whole staging.
          const imagePath = `${attachmentFolderPath}/${imageFileName}`;

          try {
            removeOpenNotices();
            await app.vault.createBinary(imagePath, new ArrayBuffer(4));
            const note = await app.vault.create(notePath, `![[${imageFileName}]]\n`);

            // The embed must be indexed, or the collector walks a note with no links and reports
            // nothing examined - which looks exactly like the regression this asserts against.
            await waitUntil({
              message: 'the staged embed was not indexed',
              predicate: () => {
                const imageFile = app.vault.getFileByPath(imagePath);
                return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length > 0;
              },
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            // The public surface rather than the command: the command acts on the ACTIVE file, which
            // would mean opening the note and waiting for the workspace to finish switching to it.
            collectAttachmentsInAbstractFiles.call(pluginRecord, [note]);

            await waitUntil({
              message: 'no notice reported that the collect moved nothing',
              predicate: () => findNothingToCollectNotice() !== null,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            return {
              attachmentStillInPlace: app.vault.getFileByPath(imagePath) !== null,
              noteStem,
              noticeText: findNothingToCollectNotice() ?? ''
            };
          } finally {
            for (const path of [notePath, imagePath]) {
              await trashIfExists(path);
            }
          }
        }

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = attachmentFolderPath;
            // Both empty, so the collect destination is the new-attachment one and the collected name is
            // the name the file already has - which is what makes every move a no-op.
            settings.collectedAttachmentFolderPath = '';
            settings.collectedAttachmentFileName = '';
          });

          const hint = await runPhase(true, 'hint');
          const plain = await runPhase(false, 'plain');
          return { hint, plain, probesFound: true };
        } finally {
          removeOpenNotices();
          await trashIfExists(attachmentFolderPath);
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorFolderPath;
            settings.collectedAttachmentFolderPath = priorCollectedFolderPath;
            settings.collectedAttachmentFileName = priorCollectedFileName;
            settings.shouldRenameCollectedAttachments = wasRenamingCollectedAttachments;
          });
        }
      },
      input: {
        attachmentFolderPath: ATTACHMENT_FOLDER_PATH,
        findPluginSettingsComponent,
        nothingToCollectPrefix: NOTHING_TO_COLLECT_PREFIX,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // The regression: the run really did move nothing, and before the fix said nothing about it.
    expect(result.hint.attachmentStillInPlace).toBe(true);
    expect(result.hint.noticeText).toContain(`${NOTHING_TO_COLLECT_PREFIX} '${result.hint.noteStem}.md'`);

    // The reporter's configuration, named in the notice rather than left to be discovered.
    expect(result.hint.noticeText).toContain(COLLECTED_FILE_NAME_SETTING);

    // Nothing is contradicting itself here, so the hint would only be noise.
    expect(result.plain.attachmentStillInPlace).toBe(true);
    expect(result.plain.noticeText).toContain(`${NOTHING_TO_COLLECT_PREFIX} '${result.plain.noteStem}.md'`);
    expect(result.plain.noticeText).not.toContain(COLLECTED_FILE_NAME_SETTING);
  }, 180_000);
});
