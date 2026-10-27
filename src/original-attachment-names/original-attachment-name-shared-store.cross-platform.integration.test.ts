import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

describe('Shared original attachment names', () => {
  it('keeps an imported arrival name after a vault rename and plugin reload, using synchronized Markdown records', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettings, lib: { pressKey, waitUntil }, renameMode }) {
        type Settings = Record<'attachmentFolderPath' | 'attachmentRenameMode' | 'generatedAttachmentFileName', string>;
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && 'generatedAttachmentFileName' in value;
        }
        const pluginId = 'obsidian-custom-attachment-location';
        const commandId = `${pluginId}:show-original-attachment-names`;
        const root = `Plugin data/${pluginId}/original-attachment-names-v1`;
        const settings = findSettings(app.plugins.getPlugin(pluginId), isSettings);
        if (!settings) {
          throw new Error('The plugin settings were not found.');
        }
        const prior = { ...settings.settings };
        const stamp = Date.now().toString();
        const arrivalName = `arrival-${stamp}.pdf`;
        const renamedPath = `shared-renamed-${stamp}.pdf`;
        const note = await app.vault.create(`shared-store-${stamp}.md`, '');
        let importedPath = '';
        let isDisabled = false;

        async function documents(folder: string): Promise<string[]> {
          if (!await app.vault.adapter.exists(folder)) {
            return [];
          }
          const listing = await app.vault.adapter.list(folder);
          const paths = [...listing.files];
          for (const child of listing.folders) {
            paths.push(...await documents(child));
          }
          return paths;
        }

        async function restoreSettings(): Promise<void> {
          const restored = findSettings(app.plugins.getPlugin(pluginId), isSettings);
          if (!restored) {
            throw new Error('The settings component did not return after reload.');
          }
          await restored.editAndSave((draft) => Object.assign(draft, prior));
        }

        try {
          await settings.editAndSave((draft) => {
            draft.attachmentFolderPath = './';
            draft.attachmentRenameMode = renameMode;
            draft.generatedAttachmentFileName = `shared-import-${stamp}`;
          });
          await app.workspace.getLeaf(false).openFile(note);
          const files = await app.importAttachments([{
            data: Promise.resolve(new TextEncoder().encode('original document').buffer),
            extension: 'pdf',
            filepath: `/Downloads/${arrivalName}`,
            name: `arrival-${stamp}`
          }], null);
          const file = files[0];
          if (!file) {
            throw new Error('No attachment was imported.');
          }
          importedPath = file.path;
          await app.vault.rename(file, renamedPath);
          // Publication is debounced; observe the real transport before reloading. Two four-second waits below
          // plus the command wait keep this callback below the transport's thirty-second default.
          await waitUntil({
            async predicate() {
              const paths = await documents(root);
              const records = paths.filter((candidate) => candidate.includes('/log-') || candidate.includes('/snapshot-'));
              for (const path of records) {
                const text = await app.vault.adapter.read(path);
                if (text.includes(renamedPath)) {
                  return true;
                }
              }
              return false;
            },
            timeoutInMilliseconds: 4000
          });
          const transportPaths = await documents(root);
          await app.plugins.disablePlugin(pluginId);
          isDisabled = true;
          await app.plugins.enablePlugin(pluginId);
          isDisabled = false;
          await waitUntil({ predicate: () => Object.hasOwn(app.commands.commands, commandId), timeoutInMilliseconds: 4000 });
          app.commands.executeCommandById(commandId);
          await waitUntil({ predicate: () => document.querySelector('.original-attachment-names-modal') !== null, timeoutInMilliseconds: 3000 });
          const row = [...document.querySelectorAll('.original-attachment-names-row')].find((candidate) => candidate.textContent.includes(renamedPath));
          const text = row?.textContent ?? '';
          await pressKey({ key: 'Escape' });
          return { arrivalName, importedPath, renamedPath, text, transportPaths };
        } finally {
          if (isDisabled) {
            await app.plugins.enablePlugin(pluginId);
          }
          if (document.querySelector('.original-attachment-names-modal')) {
            await pressKey({ key: 'Escape' });
          }
          for (const path of [note.path, importedPath, renamedPath]) {
            const file = app.vault.getAbstractFileByPath(path);
            if (file) {
              await app.fileManager.trashFile(file);
            }
          }
          await restoreSettings();
        }
      },
      input: { findPluginSettingsComponent, renameMode: 'All' },
      vaultPath: getTemporaryVault().path
    });
    expect(result.importedPath).not.toBe(result.arrivalName);
    expect(result.text).toContain(result.renamedPath);
    expect(result.text).toContain(result.arrivalName);
    expect(result.transportPaths.length).toBeGreaterThan(0);
    expect(result.transportPaths.every((path) => path.endsWith('.md'))).toBe(true);
  });
});
