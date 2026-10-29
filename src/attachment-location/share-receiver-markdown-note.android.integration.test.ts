import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

describe('a Markdown note shared through the share sheet', () => {
  it('keeps its own name at core\'s location, while an image shared with it gets the generated name', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettings }) {
        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          generatedAttachmentFileName: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldFollowObsidianAttachmentLocation: boolean;
        }
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && 'generatedAttachmentFileName' in value;
        }
        const component = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
        if (!component) {
          throw new Error('Plugin settings not loaded');
        }
        const previous = { ...component.settings };
        const stamp = Date.now().toString();
        const folder = `markdown-share-${stamp}`;
        const noteName = `Shared note ${stamp}.md`;
        await app.vault.createFolder(folder);
        const activeNote = await app.vault.create(`${folder}/active.md`, '');
        const uris: string[] = [];
        try {
          await component.editAndSave((settings) => {
            settings.attachmentFolderPath = folder;
            settings.attachmentRenameMode = 'All';
            settings.generatedAttachmentFileName = 'renamed';
            settings.shouldFollowObsidianAttachmentLocation = false;
          });
          const leaf = app.workspace.getLeaf(true);
          await leaf.openFile(activeNote);
          app.workspace.setActiveLeaf(leaf, { focus: true });

          // Appium cannot supply an Android share intent with a file payload. Blob URIs drive the real share
          // receiver, including its pre-save renaming, fetch and save.
          const shared = [
            [noteName, '# Shared'],
            ['photo.png', 'image bytes']
          ].map(([name = '', text = '']) => {
            const uri = URL.createObjectURL(new Blob([text]));
            uris.push(uri);
            return { name, uri };
          });
          await app.shareReceiver.importFiles(shared);
          leaf.detach();

          async function read(path: string): Promise<null | string> {
            const file = app.vault.getFileByPath(path);
            return file ? await app.vault.read(file) : null;
          }
          return {
            folderNames: app.vault.getFiles().filter((file) => file.parent?.path === folder).map((file) => file.name).sort((a, b) => a.localeCompare(b)),
            image: await read(`${folder}/renamed.png`),
            importPrefixedPaths: app.vault.getFiles().map((file) => file.path).filter((path) => path.includes('__IMPORT_FILES__')),
            note: await read(noteName)
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
      folderNames: ['active.md', 'renamed.png'],
      image: 'image bytes',
      importPrefixedPaths: [],
      note: '# Shared'
    });
  });
});
