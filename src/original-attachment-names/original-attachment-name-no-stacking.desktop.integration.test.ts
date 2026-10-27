import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for `{{originalAttachmentFileName}}` meaning the name an attachment ARRIVED with.
 *
 * It used to read the current name, so a collect template that prepends the note name stacked on every
 * collect: `img` became `Note-img`, then `Note-Note-img`. The sequence that showed it is the one staged here:
 * paste an image, collect, collect again. The second collect must leave the file where the first put it.
 *
 * The paste goes through `App.saveAttachment`, the sink the plugin patches, which is where a real paste and a
 * real drop end. The collects go through the plugin's public `collectAttachmentsInAbstractFiles`, because the
 * command acts on the ACTIVE file.
 */

interface NoStackingResult {
  readonly afterFirstCollect: readonly string[];
  readonly afterPaste: readonly string[];
  readonly afterSecondCollect: readonly string[];
  readonly attachmentBaseName: string;
  readonly noteBaseName: string;
  readonly probesFound: boolean;
}

interface ObsidianLibGlobal {
  readonly __obsidianLib?: Record<string, OperationQueueWrapper | undefined>;
}

/**
 * The `@mnaoumov/obsidian-lib` global operation queue, as seen from outside the library. Declared at module scope
 * because types are erased before the callback is serialized into Obsidian.
 */
interface OperationQueueState {
  readonly items?: readonly unknown[];
}

interface OperationQueueWrapper {
  readonly value?: OperationQueueState;
}

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const ATTACHMENT_FOLDER_PATH = 'oan-assets';
/*
 * Each wait is a vault write or a queued collect in a small temp vault, well under a second. The closure spends
 * this ceiling five times (two waits and three queue drains), which keeps it under the transport's 30s cap.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 4000;

describe('{{originalAttachmentFileName}} is the arrival name, so a collect template does not stack', () => {
  it('keeps the name a paste and a first collect gave the file through a second collect', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        attachmentFolderPath,
        findPluginSettingsComponent: findSettingsComponent,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<NoStackingResult> {
        interface NoStackingSettings {
          attachmentFolderPath: string;
          attachmentRenameMode: string;
          collectedAttachmentFileName: string;
          collectedAttachmentFolderPath: string;
          generatedAttachmentFileName: string;
          shouldCollectAttachmentsAutomatically: boolean;
          shouldRenameCollectedAttachments: boolean;
        }

        type CollectAttachmentsInAbstractFilesFunction = (this: unknown, abstractFiles: unknown[]) => void;

        const QUEUE_DRAIN_POLL_IN_MILLISECONDS = 100;

        function isNoStackingSettings(value: unknown): value is NoStackingSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['attachmentRenameMode'] === 'string'
            && typeof record['collectedAttachmentFileName'] === 'string'
            && typeof record['collectedAttachmentFolderPath'] === 'string'
            && typeof record['generatedAttachmentFileName'] === 'string'
            && typeof record['shouldCollectAttachmentsAutomatically'] === 'boolean'
            && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const noteBaseName = `oan-note-${stamp}`;
        const attachmentBaseName = `img-${stamp}`;
        const emptyResult: NoStackingResult = {
          afterFirstCollect: [],
          afterPaste: [],
          afterSecondCollect: [],
          attachmentBaseName,
          noteBaseName,
          probesFound: false
        };

        const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;
        const foundSettingsComponent = findSettingsComponent(pluginRecord, isNoStackingSettings);
        const foundCollect = pluginRecord?.['collectAttachmentsInAbstractFiles'];
        if (!foundSettingsComponent || typeof foundCollect !== 'function') {
          return emptyResult;
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settingsComponent = foundSettingsComponent;
        const collectAttachmentsInAbstractFiles = foundCollect as CollectAttachmentsInAbstractFilesFunction;

        const priorSettings = { ...settingsComponent.settings };

        function listAttachmentFolder(): string[] {
          return app.vault.getFiles()
            .map((file) => file.path)
            .filter((path) => path.startsWith(`${attachmentFolderPath}/`) && path.includes(stamp))
            .sort();
        }

        async function waitForQueueToDrain(): Promise<void> {
          const queueState = (window as ObsidianLibGlobal).__obsidianLib?.['queue']?.value;
          const queueDeadline = Date.now() + waitTimeoutInMilliseconds;
          while ((queueState?.items?.length ?? 0) > 0 && Date.now() < queueDeadline) {
            await sleep(QUEUE_DRAIN_POLL_IN_MILLISECONDS);
          }
        }

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

        const notePath = `${noteBaseName}.md`;
        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = attachmentFolderPath;
            // Rename on paste, to the name the file arrived with: the record is what is under test, not the template.
            settings.attachmentRenameMode = 'All';
            settings.generatedAttachmentFileName = '{{originalAttachmentFileName}}';
            settings.collectedAttachmentFolderPath = '';
            // Otherwise writing the embed collects on its own, and each collect below would find nothing left to do.
            settings.shouldCollectAttachmentsAutomatically = false;
            settings.shouldRenameCollectedAttachments = true;
            settings.collectedAttachmentFileName = '{{noteFileName}}-{{originalAttachmentFileName}}';
          });

          const note = await app.vault.create(notePath, '');
          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);
          await waitForQueueToDrain();

          const pastedFile = await app.saveAttachment(attachmentBaseName, 'png', new ArrayBuffer(8));
          // A `TFile` follows its renames, so the path the paste produced is kept as a string.
          const pastedPath = pastedFile.path;
          await app.vault.modify(note, `![[${pastedPath}]]\n`);
          await waitUntil({
            message: 'the pasted attachment\'s embed was not indexed',
            predicate: () => app.metadataCache.getBacklinksForFile(pastedFile).keys().length > 0,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          const afterPaste = listAttachmentFolder();

          collectAttachmentsInAbstractFiles.call(pluginRecord, [note]);
          await waitUntil({
            message: 'the first collect never renamed the pasted attachment',
            predicate: () => !listAttachmentFolder().includes(pastedPath),
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          await waitForQueueToDrain();
          const afterFirstCollect = listAttachmentFolder();

          collectAttachmentsInAbstractFiles.call(pluginRecord, [note]);
          // Nothing must move, so there is no change to wait for: let the queued collect run out instead.
          await sleep(QUEUE_DRAIN_POLL_IN_MILLISECONDS);
          await waitForQueueToDrain();
          const afterSecondCollect = listAttachmentFolder();

          return { afterFirstCollect, afterPaste, afterSecondCollect, attachmentBaseName, noteBaseName, probesFound: true };
        } finally {
          await trashIfExists(notePath);
          await trashIfExists(attachmentFolderPath);
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorSettings.attachmentFolderPath;
            settings.attachmentRenameMode = priorSettings.attachmentRenameMode;
            settings.collectedAttachmentFileName = priorSettings.collectedAttachmentFileName;
            settings.collectedAttachmentFolderPath = priorSettings.collectedAttachmentFolderPath;
            settings.generatedAttachmentFileName = priorSettings.generatedAttachmentFileName;
            settings.shouldCollectAttachmentsAutomatically = priorSettings.shouldCollectAttachmentsAutomatically;
            settings.shouldRenameCollectedAttachments = priorSettings.shouldRenameCollectedAttachments;
          });
        }
      },
      input: {
        attachmentFolderPath: ATTACHMENT_FOLDER_PATH,
        findPluginSettingsComponent,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);
    expect(result.afterPaste).toStrictEqual([`${ATTACHMENT_FOLDER_PATH}/${result.attachmentBaseName}.png`]);

    const collectedPath = `${ATTACHMENT_FOLDER_PATH}/${result.noteBaseName}-${result.attachmentBaseName}.png`;
    expect(result.afterFirstCollect).toStrictEqual([collectedPath]);
    // Before the arrival name was remembered, this was `<note>-<note>-img.png`.
    expect(result.afterSecondCollect).toStrictEqual([collectedPath]);
  }, 180_000);
});
