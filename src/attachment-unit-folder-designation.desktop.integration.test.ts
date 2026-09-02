import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage (G97) for the attachment-unit-folder designation this plugin publishes on the
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
      // Reading a published member needs no `await`; the callback may answer synchronously.
      callback({
        app,
        designatedFolderPath,
        plainFolderPath,
        pluginId
      }): ProbeResult {
        interface UnitFolderSettings {
          attachmentUnitFolderPaths: string[];
          isAttachmentUnitFolder(path: string): boolean;
        }

        function isUnitFolderSettings(value: unknown): value is UnitFolderSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function';
        }

        // The plugin does not expose its settings publicly, so locate the live settings object
        // (the one the patch component reads) by walking the plugin's component tree.
        function findSettings(): null | UnitFolderSettings {
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
            if (isUnitFolderSettings(record['settings'])) {
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

        const settings = findSettings();
        if (!settings) {
          return {
            isDesignatedFolderReported: false,
            isDesignationPublished: false,
            isPlainFolderReported: false,
            settingsFound: false
          };
        }

        const priorUnitFolderPaths = settings.attachmentUnitFolderPaths;
        try {
          settings.attachmentUnitFolderPaths = [designatedFolderPath];

          /*
           * Read it the way a foreign plugin does: off `app.vault` alone, with no access to this
           * plugin's instance, its settings or its exports.
           */
          const checkIsAttachmentUnitFolder = Reflect.get(
            app.vault.getAvailablePathForAttachments,
            'checkIsAttachmentUnitFolder'
          ) as CheckIsAttachmentUnitFolderFunction | undefined;
          if (!checkIsAttachmentUnitFolder) {
            return {
              isDesignatedFolderReported: false,
              isDesignationPublished: false,
              isPlainFolderReported: false,
              settingsFound: true
            };
          }

          return {
            isDesignatedFolderReported: checkIsAttachmentUnitFolder(designatedFolderPath),
            isDesignationPublished: true,
            isPlainFolderReported: checkIsAttachmentUnitFolder(plainFolderPath),
            settingsFound: true
          };
        } finally {
          settings.attachmentUnitFolderPaths = priorUnitFolderPaths;
        }
      },
      input: {
        designatedFolderPath: DESIGNATED_FOLDER_PATH,
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
