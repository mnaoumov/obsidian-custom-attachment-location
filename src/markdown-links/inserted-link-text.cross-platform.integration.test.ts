import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

describe('inserted attachment link text', () => {
  it.each([false, true])('keeps arrival names in real Obsidian links, including after rename (Markdown: %s)', async (shouldUseMarkdownLinks) => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettings, lib: { waitUntil }, obsidianModule: { Platform }, shouldUseMarkdownLinks: useMarkdownLinks }) {
        interface Settings {
          attachmentFolderPath: string;
          attachmentRenameMode: string;
          generatedAttachmentFileName: string;
          insertedLinkText: string;
          shouldFollowObsidianAttachmentLocation: boolean;
          shouldSetLinkDisplayTextToAttachmentFileName: boolean;
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
        const folder = `inserted-link-${stamp}`;
        await app.vault.createFolder(folder);
        const note = await app.vault.create(`${folder}/note.md`, '');
        try {
          app.vault.setConfig('useMarkdownLinks', useMarkdownLinks);
          await component.editAndSave((settings) => {
            settings.attachmentFolderPath = folder;
            settings.attachmentRenameMode = 'All';
            settings.generatedAttachmentFileName = 'renamed';
            settings.insertedLinkText = '{{originalAttachmentFileName}}';
            settings.shouldFollowObsidianAttachmentLocation = false;
            settings.shouldSetLinkDisplayTextToAttachmentFileName = false;
          });
          const leaf = app.workspace.getLeaf(true);
          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          app.workspace.setActiveLeaf(leaf, { focus: true });
          await waitUntil({
            message: 'the Markdown editor to become visible',
            predicate: () => !!leaf.view.containerEl.querySelector('.cm-content'),
            timeoutInMilliseconds: 5000
          });
          const editor = leaf.view.containerEl.querySelector('.cm-content');
          if (!editor) {
            throw new Error('Markdown editor missing');
          }
          if (Platform.isDesktopApp) {
            const transfer = new DataTransfer();
            transfer.items.add(new File(['%PDF-1.4'], 'dropped report.pdf', { type: 'application/pdf' }));
            const rect = editor.getBoundingClientRect();
            // eslint-disable-next-line obsidian-dev-toolkit/no-untrusted-input-events -- Electron's trusted input cannot express an OS file drag; this drives Obsidian's real drop/save/link handlers.
            editor.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, clientX: rect.left + 5, clientY: rect.top + 5, dataTransfer: transfer }));
            await waitUntil({
              message: 'the dropped PDF to be saved and linked with its arrival name',
              predicate: async () => {
                const content = await app.vault.read(note);
                return content.includes('dropped report');
              },
              timeoutInMilliseconds: 10_000
            });
          } else {
            // Mobile has no OS file-drag source; exercise the same attachment saver and link generator.
            const file = await app.saveAttachment('dropped report', 'pdf', new TextEncoder().encode('%PDF-1.4').buffer);
            await app.vault.modify(note, app.fileManager.generateMarkdownLink(file, note.path));
          }
          const droppedContent = await app.vault.read(note);
          // Drive the same saving sink for names the host filesystem cannot give a real drag source.
          const links: string[] = [];
          const laterLinks: string[] = [];
          for (const name of ['report', '300', '1920x1080', 'a|b]c[d#e^f']) {
            const file = await app.saveAttachment(name, 'pdf', new TextEncoder().encode('%PDF-1.4').buffer);
            links.push(app.fileManager.generateMarkdownLink(file, note.path));
            await app.vault.rename(file, `${folder}/later-${links.length.toString()}.pdf`);
            laterLinks.push(app.fileManager.generateMarkdownLink(file, note.path));
          }
          await component.editAndSave((settings) => {
            settings.insertedLinkText = '';
          });
          const defaultFile = app.vault.getFileByPath(`${folder}/later-1.pdf`);
          if (!defaultFile) {
            throw new Error('Renamed attachment missing');
          }
          leaf.detach();
          return { defaultLink: app.fileManager.generateMarkdownLink(defaultFile, note.path), droppedContent, laterLinks, links };
        } finally {
          app.vault.setConfig('useMarkdownLinks', previousMarkdown);
          await component.editAndSave((settings) => {
            Object.assign(settings, previous);
          });
        }
      },
      input: { findPluginSettingsComponent, shouldUseMarkdownLinks },
      vaultPath: getTemporaryVault().path
    });
    const labels = ['report', '300', '1920x1080', 'a｜b］c［d＃e＾f'];
    expect(result.droppedContent).toContain(shouldUseMarkdownLinks ? '[dropped report](' : '|dropped report]]');
    for (const [index, label] of labels.entries()) {
      expect(result.links[index]).toContain(shouldUseMarkdownLinks ? `[${label}](` : `|${label}]]`);
      expect(result.laterLinks[index]).toContain(shouldUseMarkdownLinks ? `[${label}](` : `|${label}]]`);
      expect(result.links[index]).toContain('renamed');
      expect(result.laterLinks[index]).toContain('later-');
    }
    expect(result.defaultLink).not.toContain('report');
  });
});
