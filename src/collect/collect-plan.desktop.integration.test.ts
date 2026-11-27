import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * A folder collect shows its plan before anything moves: the plan names the attachment and the destination the
 * collect then uses, Cancel leaves the vault as it was, and Apply plan runs the collect.
 *
 * The run goes through the plugin's own `collectAttachmentsInAbstractFiles`, which is the folder command's path minus
 * the active-file lookup, and the dialog is answered by its real buttons.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const PLAN_MODAL_SELECTOR = '.custom-attachment-location-collect-plan-modal';
// Each wait is a dialog opening or a queued collect in a small temporary vault, well under a second. Five such waits
// and the settle after Cancel stay under the transport's 30 s cap on one closure.
const WAIT_TIMEOUT_IN_MILLISECONDS = 4000;

interface PlanProbeResult {
  readonly afterApplyPath: null | string;
  readonly afterCancelPath: null | string;
  readonly applyButtonText: string;
  readonly planListing: string;
  readonly plannedTargetPath: string;
  readonly planSummary: string;
  readonly probesFound: boolean;
}

describe('Collect plan for a folder run', () => {
  it('shows the plan, leaves the vault alone on Cancel, and collects to the planned path on Apply plan', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        findPluginSettingsComponent: findSettingsComponent,
        lib: { waitUntil },
        planModalSelector,
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<PlanProbeResult> {
        interface CollectPlanSettings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          collectedAttachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldRenameCollectedAttachments: boolean;
        }

        type CollectAttachmentsInAbstractFilesFunction = (this: unknown, abstractFiles: unknown[]) => void;

        function isCollectPlanSettings(value: unknown): value is CollectPlanSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['collectedAttachmentFolderPath'] === 'string'
            && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
        }

        const emptyResult: PlanProbeResult = {
          afterApplyPath: null,
          afterCancelPath: null,
          applyButtonText: '',
          planListing: '',
          plannedTargetPath: '',
          planSummary: '',
          probesFound: false
        };

        const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;
        const foundSettingsComponent = findSettingsComponent(pluginRecord, isCollectPlanSettings);
        const foundCollect = pluginRecord?.['collectAttachmentsInAbstractFiles'];
        if (!foundSettingsComponent || typeof foundCollect !== 'function') {
          return emptyResult;
        }
        const settingsComponent = foundSettingsComponent;
        const collectAttachmentsInAbstractFiles = foundCollect as CollectAttachmentsInAbstractFilesFunction;

        const priorFolderPath = settingsComponent.settings.attachmentFolderPath;
        const priorCollectedFolderPath = settingsComponent.settings.collectedAttachmentFolderPath;
        const wasRenamingCollectedAttachments = settingsComponent.settings.shouldRenameCollectedAttachments;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folderPath = `cp-${stamp}`;
        const imageFileName = `cp-img-${stamp}.png`;
        const imagePath = `${folderPath}/loose/${imageFileName}`;
        const plannedTargetPath = `${folderPath}/assets/${imageFileName}`;

        function findPlanModal(): HTMLElement | null {
          return document.querySelector<HTMLElement>(planModalSelector);
        }

        async function openPlan(): Promise<HTMLElement> {
          const folder = app.vault.getFolderByPath(folderPath);
          collectAttachmentsInAbstractFiles.call(pluginRecord, [folder]);
          await waitUntil({
            message: 'the collect plan dialog never opened',
            predicate: () => findPlanModal() !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          const modal = findPlanModal();
          if (!modal) {
            throw new Error('The collect plan dialog closed before it was read.');
          }
          return modal;
        }

        function findButton(modal: HTMLElement, isApply: boolean): HTMLButtonElement {
          const buttons = [...modal.querySelectorAll<HTMLButtonElement>('button')];
          const button = buttons.find((candidate) => candidate.classList.contains('mod-cta') === isApply);
          if (!button) {
            throw new Error(`The collect plan dialog has no ${isApply ? 'apply' : 'cancel'} button.`);
          }
          return button;
        }

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = './assets';
            settings.collectedAttachmentFolderPath = '';
            // The name must survive the collect, so the planned path is the folder change alone.
            settings.shouldRenameCollectedAttachments = false;
          });

          await app.vault.createFolder(`${folderPath}/loose`);
          await app.vault.createBinary(imagePath, new ArrayBuffer(4));
          await app.vault.create(`${folderPath}/note.md`, `![[loose/${imageFileName}]]\n`);
          await app.vault.create(`${folderPath}/plain.md`, 'No attachments here.\n');

          await waitUntil({
            message: 'the staged embed was not indexed',
            predicate: () => {
              const imageFile = app.vault.getFileByPath(imagePath);
              return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length > 0;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const cancelModal = await openPlan();
          const planSummary = cancelModal.querySelector('.custom-attachment-location-collect-plan-summary')?.textContent ?? '';
          const planListing = cancelModal.querySelector('.custom-attachment-location-collect-plan-notes')?.textContent ?? '';
          const applyButtonText = findButton(cancelModal, true).textContent;
          findButton(cancelModal, false).click();
          await waitUntil({
            message: 'the collect plan dialog did not close on Cancel',
            predicate: () => findPlanModal() === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          // A cancelled plan collects nothing, so the attachment is still where it was a moment later.
          await sleep(500);
          const afterCancelPath = app.vault.getFileByPath(imagePath)?.path ?? null;

          const applyModal = await openPlan();
          findButton(applyModal, true).click();
          await waitUntil({
            message: 'the attachment never reached its planned path, so the applied plan did not collect it',
            predicate: () => app.vault.getFileByPath(plannedTargetPath) !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          const afterApplyPath = app.vault.getFileByPath(plannedTargetPath)?.path ?? null;

          return { afterApplyPath, afterCancelPath, applyButtonText, planListing, plannedTargetPath, planSummary, probesFound: true };
        } finally {
          const folder = app.vault.getFolderByPath(folderPath);
          if (folder) {
            try {
              await app.fileManager.trashFile(folder);
            } catch {
              // Already gone, which is the outcome this wanted anyway.
            }
          }
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorFolderPath;
            settings.collectedAttachmentFolderPath = priorCollectedFolderPath;
            settings.shouldRenameCollectedAttachments = wasRenamingCollectedAttachments;
          });
        }
      },
      input: {
        findPluginSettingsComponent,
        planModalSelector: PLAN_MODAL_SELECTOR,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);
    expect(result.applyButtonText).toBe('Apply plan');
    expect(result.planSummary).toBe('Plan: 1 to move, 0 to rename, 0 to copy, 0 to merge, 0 to ask about, 0 already in place, 0 skipped.');
    expect(result.planListing).toContain(`Move: ${result.plannedTargetPath.replace('/assets/', '/loose/')} → ${result.plannedTargetPath}`);
    expect(result.afterCancelPath).toBe(result.plannedTargetPath.replace('/assets/', '/loose/'));
    expect(result.afterApplyPath).toBe(result.plannedTargetPath);
  }, 180_000);
});
