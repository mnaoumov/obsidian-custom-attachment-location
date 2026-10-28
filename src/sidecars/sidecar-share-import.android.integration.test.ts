import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

describe('sidecars shared through the share sheet', () => {
  it('names a companion after its base, with the suffix the whole group needs, and keeps an orphan\'s name', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettings }) {
        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          duplicateNameSeparator: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          generatedAttachmentFileName: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldFollowObsidianAttachmentLocation: boolean;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          sidecarExtensions: string[];
        }
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && 'sidecarExtensions' in value;
        }
        const component = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
        if (!component) {
          throw new Error('Plugin settings not loaded');
        }
        const previous = { ...component.settings };
        const folder = `sidecar-share-${Date.now().toString()}`;
        await app.vault.createFolder(folder);
        const note = await app.vault.create(`${folder}/note.md`, '');
        // Only the companion's name is taken, so core alone would save `renamed 1.html` beside `renamed.html.p7s`.
        await app.vault.create(`${folder}/renamed.html.p7s`, 'occupant');
        const uris: string[] = [];
        try {
          await component.editAndSave((settings) => {
            settings.attachmentFolderPath = folder;
            settings.attachmentRenameMode = 'All';
            settings.duplicateNameSeparator = ' ';
            settings.generatedAttachmentFileName = 'renamed';
            settings.shouldFollowObsidianAttachmentLocation = false;
            settings.sidecarExtensions = ['p7s'];
          });
          const leaf = app.workspace.getLeaf(true);
          await leaf.openFile(note);
          app.workspace.setActiveLeaf(leaf, { focus: true });

          // Appium cannot supply an Android share intent with a file payload. Blob URIs drive the real share
          // receiver, including its pre-save renaming, fetch and save.
          const shared = [
            ['document.html.p7s', 'signature'],
            ['document.html', '<html></html>'],
            ['lonely.p7s', 'orphan']
          ].map(([name = '', text = '']) => {
            const uri = URL.createObjectURL(new Blob([text]));
            uris.push(uri);
            return { name, uri };
          });
          await app.shareReceiver.importFiles(shared);
          leaf.detach();

          async function read(name: string): Promise<null | string> {
            const file = app.vault.getFileByPath(`${folder}/${name}`);
            return file ? await app.vault.read(file) : null;
          }
          return {
            base: await read('renamed 1.html'),
            companion: await read('renamed 1.html.p7s'),
            names: app.vault.getFiles().filter((file) => file.parent?.path === folder).map((file) => file.name).sort((a, b) => a.localeCompare(b)),
            occupant: await read('renamed.html.p7s'),
            orphan: await read('lonely.p7s')
          };
        } finally {
          for (const uri of uris) {
            URL.revokeObjectURL(uri);
          }
          await component.editAndSave((settings) => {
            Object.assign(settings, previous);
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });

    expect(result).toEqual({
      base: '<html></html>',
      companion: 'signature',
      names: ['lonely.p7s', 'note.md', 'renamed 1.html', 'renamed 1.html.p7s', 'renamed.html.p7s'].sort((a, b) => a.localeCompare(b)),
      occupant: 'occupant',
      orphan: 'orphan'
    });
  });
});
