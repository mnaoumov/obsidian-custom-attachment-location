import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * A custom token saved other than through the settings tab: a script's `editAndSave`, or a `data.json` replaced by
 * sync. Only the tab and the plugin load used to register custom tokens, so until the next reload a template naming
 * the new token was refused as invalid and silently replaced by the default.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';

interface ProbeResult {
  readonly sameEditFolderPath: string;
  readonly sameEditPath: string;
  readonly separateEditsFolderPath: string;
  readonly separateEditsPath: string;
  readonly settingsFound: boolean;
}

describe('Custom tokens saved without the settings tab', () => {
  it('registers them in the save that stores them, with no plugin reload', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, pluginId }): Promise<ProbeResult> {
        interface TokenSettings {
          attachmentFolderPath: string;
          // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key.
          customTokensStr: string;
          shouldFollowObsidianAttachmentLocation: boolean;
        }

        function isTokenSettings(value: unknown): value is TokenSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string'
            && typeof (value as Record<string, unknown>)['customTokensStr'] === 'string';
        }

        const foundSettingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isTokenSettings);
        if (!foundSettingsComponent) {
          return { sameEditFolderPath: '', sameEditPath: '', separateEditsFolderPath: '', separateEditsPath: '', settingsFound: false };
        }
        const settingsComponent = foundSettingsComponent;
        const prior = { ...settingsComponent.settings };

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const notePath = `cts-note-${stamp}.md`;

        try {
          const note = await app.vault.create(notePath, 'body\n');

          // The shape `demoSetup.ts` used to need a reload for: the tokens in one save, the template in the next.
          await settingsComponent.editAndSave((settings) => {
            // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key.
            settings.customTokensStr = 'registerCustomToken(\'separateToken\', () => \'separate-value\');';
            settings.shouldFollowObsidianAttachmentLocation = false;
          });
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = 'cts-{{separateToken}}';
          });
          const separateEditsFolderPath = settingsComponent.settings.attachmentFolderPath;
          const separateEditsPath = await app.vault.getAvailablePathForAttachments('image', 'png', note);

          // Both in ONE save, so the template is validated in the same pass that stores the token.
          await settingsComponent.editAndSave((settings) => {
            // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key.
            settings.customTokensStr = 'registerCustomToken(\'sameToken\', () => \'same-value\');';
            settings.attachmentFolderPath = 'cts-{{sameToken}}';
          });
          const sameEditFolderPath = settingsComponent.settings.attachmentFolderPath;
          const sameEditPath = await app.vault.getAvailablePathForAttachments('image', 'png', note);

          return { sameEditFolderPath, sameEditPath, separateEditsFolderPath, separateEditsPath, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = prior.attachmentFolderPath;
            // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key.
            settings.customTokensStr = prior.customTokensStr;
            settings.shouldFollowObsidianAttachmentLocation = prior.shouldFollowObsidianAttachmentLocation;
          });
          const note = app.vault.getAbstractFileByPath(notePath);
          if (note) {
            await app.fileManager.trashFile(note);
          }
        }
      },
      input: {
        findPluginSettingsComponent,
        pluginId: PLUGIN_ID
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.separateEditsFolderPath).toBe('cts-{{separateToken}}');
    expect(result.separateEditsPath.split('/').slice(0, -1).join('/')).toBe('cts-separate-value');
    expect(result.sameEditFolderPath).toBe('cts-{{sameToken}}');
    expect(result.sameEditPath.split('/').slice(0, -1).join('/')).toBe('cts-same-value');
  }, 180_000);
});
