import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for the attachment-unit-folder designation this plugin publishes on the
 * patched `Vault.getAvailablePathForAttachments`, beside `extended`.
 *
 * The reader that needs it is another plugin: Advanced Rename and Delete Handler owns the delete
 * interception from 12.0.0 and has to keep a designated folder whole when it rescues an attachment out
 * of a deleted note's area (issue #70), while resolving attachment policy without knowing which plugin
 * supplies it. So what matters is not that the setting works — other suites cover that — but that the
 * answer is readable off the live vault by a caller holding nothing but `app`, which is exactly what
 * this drives.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const DESIGNATED_FOLDER_PATH = 'Materials/page_files';
const PLAIN_FOLDER_PATH = 'Materials';

type CheckIsAttachmentUnitFolderFunction = (folderPath: string) => boolean;

interface ProbeResult {
  readonly isDesignatedFolderReported: boolean;
  readonly isDesignationPublished: boolean;
  readonly isPlainFolderReported: boolean;
  readonly settingsFound: boolean;
}

describe('The attachment unit folder designation is published on the vault', () => {
  it('answers for a designated folder and for a plain one', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        designatedFolderPath,
        findPluginSettingsComponent: findSettingsComponent,
        plainFolderPath,
        pluginId
      }): Promise<ProbeResult> {
        interface UnitFolderSettings {
          attachmentUnitFolderPaths: string[];
          isAttachmentUnitFolder: (path: string) => boolean;
        }

        function isUnitFolderSettings(value: unknown): value is UnitFolderSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isUnitFolderSettings);
        if (!settingsComponent) {
          return {
            isDesignatedFolderReported: false,
            isDesignationPublished: false,
            isPlainFolderReported: false,
            settingsFound: false
          };
        }

        const priorUnitFolderPaths = settingsComponent.settings.attachmentUnitFolderPaths;
        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentUnitFolderPaths = [designatedFolderPath];
          });

          /*
           * Read it the way a foreign plugin does: off `app.vault` alone, with no access to this
           * plugin's instance, its settings or its exports.
           */
          const checkIsAttachmentUnitFolder = Reflect.get(
            app.vault.getAvailablePathForAttachments,
            'checkIsAttachmentUnitFolder'
          ) as CheckIsAttachmentUnitFolderFunction | undefined;
          return checkIsAttachmentUnitFolder
            ? {
              isDesignatedFolderReported: checkIsAttachmentUnitFolder(designatedFolderPath),
              isDesignationPublished: true,
              isPlainFolderReported: checkIsAttachmentUnitFolder(plainFolderPath),
              settingsFound: true
            }
            : {
              isDesignatedFolderReported: false,
              isDesignationPublished: false,
              isPlainFolderReported: false,
              settingsFound: true
            };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentUnitFolderPaths = priorUnitFolderPaths;
          });
        }
      },
      input: {
        designatedFolderPath: DESIGNATED_FOLDER_PATH,
        findPluginSettingsComponent,
        plainFolderPath: PLAIN_FOLDER_PATH,
        pluginId: PLUGIN_ID
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.isDesignationPublished).toBe(true);
    expect(result.isDesignatedFolderReported).toBe(true);
    expect(result.isPlainFolderReported).toBe(false);
  }, 120_000);
});
