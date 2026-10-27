import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for the attachment-unit-folder designation this plugin publishes through its plugin API,
 * as `isAttachmentUnitFolder`. Until 15.0.0 it was also grafted onto the patched
 * `Vault.getAvailablePathForAttachments` as `checkIsAttachmentUnitFolder`.
 *
 * The reader that needs it is another plugin: `Advanced Rename and Delete Handler` owns the delete
 * interception from 12.0.0 and has to keep a designated folder whole when it rescues an attachment out
 * of a deleted note's area (issue #70), while resolving attachment policy without knowing which plugin
 * supplies it. So what matters is not that the setting works — other suites cover that — but that the
 * answer is readable through the plugin-API registry by a caller holding nothing of this plugin's, which is
 * exactly what this drives.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const DESIGNATED_FOLDER_PATH = 'Materials/page_files';
const PLAIN_FOLDER_PATH = 'Materials';

interface ProbeResult {
  readonly isDesignatedFolderReported: boolean;
  readonly isDesignationPublished: boolean;
  readonly isPlainFolderReported: boolean;
  readonly settingsFound: boolean;
}

describe('The attachment unit folder designation is published through the plugin API', () => {
  it('answers for a designated folder and for a plain one', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        designatedFolderPath,
        findPluginSettingsComponent: findSettingsComponent,
        plainFolderPath,
        pluginId
      }): Promise<ProbeResult> {
        interface ApiLike {
          isAttachmentUnitFolder: (params: UnitFolderParams) => boolean;
        }

        interface ApiRecord {
          readonly api: unknown;
          readonly isRevoked: boolean;
        }

        interface ObsidianLibWrapper {
          readonly __obsidianLib: ObsidianLibState;
        }

        interface ObsidianLibState {
          readonly pluginApiRegistry?: RegistryWrapper;
        }

        interface RegistryWrapper {
          readonly value?: RegistryValue;
        }

        interface RegistryValue {
          readonly records?: Record<string, ApiRecord[]>;
        }

        interface UnitFolderParams {
          readonly folderPath: string;
        }

        interface UnitFolderSettings {
          attachmentUnitFolderPaths: string[];
          isAttachmentUnitFolder: (path: string) => boolean;
        }

        function isApiLike(value: unknown): value is ApiLike {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function';
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
           * Read it the way a foreign plugin does: through the registry, with no access to this plugin's
           * instance, its settings or its exports.
           */
          const record = (window as Partial<ObsidianLibWrapper>).__obsidianLib?.pluginApiRegistry?.value?.records?.[pluginId]
            ?.find((candidate) => !candidate.isRevoked);
          const api = record && isApiLike(record.api) ? record.api : null;
          const checkIsAttachmentUnitFolder = api ? (folderPath: string): boolean => api.isAttachmentUnitFolder({ folderPath }) : null;
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
