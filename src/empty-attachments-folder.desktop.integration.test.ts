import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for issue #26: with "Location for new attachments" = `./_/{{noteFileName}}`, a
 * *dry* `getAvailablePathForAttachments` resolution (Obsidian core / third-party plugins probing where
 * an attachment would land) must NOT eagerly create the empty per-note attachment folder. A real save
 * that goes through the base method (audio recorder, downloaded-image paste, dropped-file import) must
 * still place the attachment correctly, materializing its folder at write time.
 */

interface ErrorLike {
  readonly message?: string;
}

interface ProbeResult {
  readonly folderExistsAfterDryProbe: boolean;
  readonly folderExistsAfterRealSave: boolean;
  readonly realSaveError: string;
  readonly realSavePath: string;
  readonly resolvedFolder: string;
  readonly settingsFound: boolean;
}

describe('Empty attachments folder is not created on a dry resolution (issue #26)', () => {
  it('creates the per-note folder only when an attachment is actually saved', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent }): Promise<ProbeResult> {
        interface Settings {
          attachmentFolderPath: string;
          generatedAttachmentFileName: string;
        }
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string'
            && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string';
        }
        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
        if (!settingsComponent) {
          return {
            folderExistsAfterDryProbe: false,
            folderExistsAfterRealSave: false,
            realSaveError: '',
            realSavePath: '',
            resolvedFolder: '',
            settingsFound: false
          };
        }

        const priorFolderPath = settingsComponent.settings.attachmentFolderPath;
        await settingsComponent.editAndSave((settings) => {
          settings.attachmentFolderPath = './_/{{noteFileName}}';
        });

        try {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const noteBaseName = `EmptyFolderNote-${stamp}`;
          const note = await app.vault.create(`${noteBaseName}.md`, '');
          await app.workspace.getLeaf(false).openFile(note);
          await sleep(300);

          const resolvedFolder = `_/${noteBaseName}`;

          // A dry resolution (what core / other plugins do). This must NOT create the folder.
          await app.vault.getAvailablePathForAttachments('probe-attachment', 'png', note);
          await sleep(300);
          const isFolderExistsAfterDryProbe = Boolean(app.vault.getAbstractFileByPath(resolvedFolder));

          // A real save through the base method (audio-recorder style): resolve then write.
          let realSaveError = '';
          let realSavePath = '';
          try {
            realSavePath = await app.vault.getAvailablePathForAttachments('Recording', 'webm', note);
            await app.vault.createBinary(realSavePath, new ArrayBuffer(8));
          } catch (error) {
            realSaveError = String((error as ErrorLike).message ?? error);
          }
          const isFolderExistsAfterRealSave = Boolean(app.vault.getAbstractFileByPath(realSavePath));

          return {
            folderExistsAfterDryProbe: isFolderExistsAfterDryProbe,
            folderExistsAfterRealSave: isFolderExistsAfterRealSave,
            realSaveError,
            realSavePath,
            resolvedFolder,
            settingsFound: true
          };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorFolderPath;
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // Issue #26: a dry resolution must not eagerly create the empty per-note attachment folder.
    expect(result.folderExistsAfterDryProbe).toBe(false);

    // A real save through the base method must still succeed and place the attachment in the folder.
    expect(result.realSaveError).toBe('');
    expect(result.realSavePath).toMatch(/^_\/EmptyFolderNote-.*\/Recording\.webm$/);
    expect(result.folderExistsAfterRealSave).toBe(true);
  }, 120_000);
});
