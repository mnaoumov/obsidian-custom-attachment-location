import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { installReleasedPlugin } from '../../scripts/helpers/download-released-plugin.ts';
import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';
import { waitForPluginSettingsLoaded } from '../../scripts/helpers/plugin-settings-loaded-wait.ts';

/*
 * `Better Markdown Links` replaces `fileManager.generateMarkdownLink` and never calls the method it wraps. It loads
 * after this plugin in a typical vault, so its patch landed on top of this plugin's, and a dropped attachment got
 * Obsidian's default link text, its renamed file name, whatever `Inserted link text` said. This suite enables the
 * RELEASED plugin after this one, which is that order, and drops a file for each of the two name tokens.
 */

const BETTER_MARKDOWN_LINKS_PLUGIN_ID = 'better-markdown-links';
const BETTER_MARKDOWN_LINKS_REPO = 'mnaoumov/obsidian-better-markdown-links';
const BETTER_MARKDOWN_LINKS_VERSION = '6.7.1';

interface ProbeResult {
  readonly currentNameLine: string;
  readonly linkBeforeDrop: string;
  readonly originalNameLine: string;
}

describe('inserted link text with Better Markdown Links enabled after this plugin', () => {
  it('uses the arrival name for {{originalAttachmentFileName}} and the saved name for {{attachmentFileName}}', async () => {
    await waitForPluginSettingsLoaded();
    const vaultPath = getTemporaryVault().path;
    await installReleasedPlugin({ pluginId: BETTER_MARKDOWN_LINKS_PLUGIN_ID, repo: BETTER_MARKDOWN_LINKS_REPO, vaultPath, version: BETTER_MARKDOWN_LINKS_VERSION });

    const result = await evalInObsidian({
      async callback({ app, betterMarkdownLinksPluginId, findPluginSettingsComponent: findSettings, lib: { waitUntil } }): Promise<ProbeResult> {
        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          generatedAttachmentFileName: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          insertedLinkText: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldFollowObsidianAttachmentLocation: boolean;
        }
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && 'insertedLinkText' in value;
        }
        const component = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
        if (!component) {
          throw new Error('Plugin settings not loaded');
        }
        const previous = { ...component.settings };
        const previousMarkdown = app.vault.getConfig('useMarkdownLinks');
        const stamp = Date.now().toString();
        const folder = `inserted-link-better-markdown-links-${stamp}`;
        await app.vault.createFolder(folder);
        const note = await app.vault.create(`${folder}/note.md`, '');
        const leaf = app.workspace.getLeaf(true);
        try {
          app.vault.setConfig('useMarkdownLinks', true);
          await component.editAndSave((settings) => {
            settings.attachmentFolderPath = folder;
            settings.attachmentRenameMode = 'All';
            settings.generatedAttachmentFileName = 'renamed';
            settings.insertedLinkText = '{{originalAttachmentFileName}}';
            settings.shouldFollowObsidianAttachmentLocation = false;
          });

          const methodBefore = app.fileManager.generateMarkdownLink;
          await app.plugins.loadManifests();
          await app.plugins.enablePlugin(betterMarkdownLinksPluginId);
          await waitUntil({
            message: 'Better Markdown Links to patch generateMarkdownLink',
            predicate: () => app.fileManager.generateMarkdownLink !== methodBefore,
            timeoutInMilliseconds: 5000
          });

          // The precondition: an existing attachment's link, asked for outside a paste or a drop, skips this plugin.
          const existing = await app.vault.createBinary(`${folder}/existing.pdf`, new TextEncoder().encode('%PDF-1.4').buffer);
          const linkBeforeDrop = app.fileManager.generateMarkdownLink(existing, note.path);

          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          app.workspace.setActiveLeaf(leaf, { focus: true });
          await waitUntil({
            message: 'the Markdown editor to become visible',
            predicate: () => !!leaf.view.containerEl.querySelector('.cm-content'),
            timeoutInMilliseconds: 5000
          });

          async function drop(fileName: string, expectedText: string): Promise<string> {
            const editor = leaf.view.containerEl.querySelector('.cm-content');
            if (!editor) {
              throw new Error('Markdown editor missing');
            }
            const transfer = new DataTransfer();
            transfer.items.add(new File(['%PDF-1.4'], fileName, { type: 'application/pdf' }));
            const rect = editor.getBoundingClientRect();
            // eslint-disable-next-line obsidian-dev-toolkit/no-untrusted-input-events -- Electron's trusted input cannot express an OS file drag; this drives Obsidian's real drop/save/link handlers.
            editor.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, clientX: rect.left + 5, clientY: rect.top + 5, dataTransfer: transfer }));
            let line = '';
            await waitUntil({
              message: `the dropped ${fileName} to be linked`,
              predicate: async () => {
                const content = await app.vault.read(note);
                line = content.split('\n').find((candidate) => candidate.includes(expectedText)) ?? '';
                return line !== '' || content.split('\n').some((candidate) => candidate.includes('renamed'));
              },
              timeoutInMilliseconds: 8000
            });
            const content = await app.vault.read(note);
            await app.vault.modify(note, '');
            return line || content;
          }

          const originalNameLine = await drop('arrival report.pdf', '[arrival report]');
          await component.editAndSave((settings) => {
            settings.insertedLinkText = '{{attachmentFileName}}';
          });
          const currentNameLine = await drop('second report.pdf', '[renamed');
          return { currentNameLine, linkBeforeDrop, originalNameLine };
        } finally {
          leaf.detach();
          await app.plugins.disablePlugin(betterMarkdownLinksPluginId);
          app.vault.setConfig('useMarkdownLinks', previousMarkdown);
          await component.editAndSave((settings) => {
            Object.assign(settings, previous);
          });
          const pluginFolderPath = `${app.vault.configDir}/plugins/${betterMarkdownLinksPluginId}`;
          if (await app.vault.adapter.exists(pluginFolderPath)) {
            await app.vault.adapter.rmdir(pluginFolderPath, true);
          }
          // So the removed plugin stops appearing in `app.plugins.manifests` for every later suite.
          await app.plugins.loadManifests();
          const folderFile = app.vault.getFolderByPath(folder);
          if (folderFile) {
            await app.fileManager.trashFile(folderFile);
          }
        }
      },
      input: { betterMarkdownLinksPluginId: BETTER_MARKDOWN_LINKS_PLUGIN_ID, findPluginSettingsComponent },
      vaultPath
    });

    // Its own empty text: this plugin's `existing` never reached it.
    expect(result.linkBeforeDrop).toBe('[](<existing.pdf>)');
    // A dropped PDF is embedded. The arrival name, without the extension, and the saved file's name; never empty.
    expect(result.originalNameLine).toMatch(/^!?\[arrival report\]\(/);
    expect(result.currentNameLine).toMatch(/^!?\[renamed(?: \d+)?\]\(/);
  }, 120_000);
});
