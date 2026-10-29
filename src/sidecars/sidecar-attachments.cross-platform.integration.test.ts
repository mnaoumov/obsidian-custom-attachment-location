// Cspell:words УХВАЛА
import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

describe('sidecar attachment groups', () => {
  it('imports one random base name, carries its signature on rename, and preserves an orphan', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettings, lib: { waitUntil }, obsidianModule: { MarkdownView, Platform } }) {
        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
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
        const settingsComponent = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
        if (!settingsComponent) {
          throw new Error('Sidecar settings not loaded');
        }
        const previous = { ...settingsComponent.settings };
        const folder = `sidecars-${Date.now().toString()}`;
        await app.vault.createFolder(folder);
        const note = await app.vault.create(`${folder}/note.md`, '');
        const leaf = app.workspace.getLeaf(true);
        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = folder;
            settings.attachmentRenameMode = 'All';
            settings.generatedAttachmentFileName = '{{random}}';
            settings.shouldFollowObsidianAttachmentLocation = false;
            settings.sidecarExtensions = ['p7s', 'srt'];
          });
          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          app.workspace.setActiveLeaf(leaf, { focus: true });
          await waitUntil({
            message: 'the editor to be visible before dropping paired files',
            predicate: () => !!leaf.view.containerEl.querySelector('.cm-content'),
            timeoutInMilliseconds: 5000
          });
          const html = '<html>Document to sign</html>';
          await waitUntil({
            message: 'the clipboard interception to finish loading before the first drop',
            // Obsidian's own `insertFiles` is an anonymous function, so its name proves nothing. A monkey-around wrapper
            // Chains its prototype to the method it wraps, which the unpatched method never has.
            predicate: () =>
              leaf.view instanceof MarkdownView
              && Object.getPrototypeOf(leaf.view.editMode.clipboardManager.insertFiles) !== Function.prototype,
            timeoutInMilliseconds: 5000
          });
          const signature = 'detached signature bytes';
          if (Platform.isDesktopApp) {
            const editor = leaf.view.containerEl.querySelector('.cm-content');
            if (!editor) {
              throw new Error('Editor missing');
            }
            const transfer = new DataTransfer();
            transfer.items.add(new File([signature], 'УХВАЛА.html.p7s'));
            transfer.items.add(new File([html], 'УХВАЛА.html', { type: 'text/html' }));
            const rect = editor.getBoundingClientRect();
            // eslint-disable-next-line obsidian-dev-toolkit/no-untrusted-input-events -- Electron's trusted input cannot express an OS file drag; this exercises Obsidian's actual drop, import and link handlers.
            editor.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, clientX: rect.left + 5, clientY: rect.top + 5, dataTransfer: transfer }));
          } else {
            // Android has no OS file-drag source in this harness; use the same batch import sink.
            const files = await app.importAttachments([
              { data: Promise.resolve(new TextEncoder().encode(signature).buffer), extension: 'p7s', name: 'УХВАЛА.html' },
              { data: Promise.resolve(new TextEncoder().encode(html).buffer), extension: 'html', name: 'УХВАЛА' }
            ], null);
            await app.vault.modify(note, files.map((file) => app.fileManager.generateMarkdownLink(file, note.path)).join('\n'));
          }
          await waitUntil({
            message: 'the paired attachments and both links to be saved',
            predicate: async () => {
              const content = await app.vault.read(note);
              return app.vault.getFiles().filter((file) => file.path.startsWith(`${folder}/`) && file.extension !== 'md').length === 2 && content.includes('.p7s');
            },
            timeoutInMilliseconds: 10_000
          });
          const base = app.vault.getFiles().find((file) => file.path.startsWith(`${folder}/`) && file.extension === 'html');
          if (!base) {
            throw new Error('Base HTML missing');
          }
          const importedBaseName = base.name;
          const paired = app.vault.getFileByPath(`${base.path}.p7s`);
          if (!paired) {
            throw new Error(`Signature did not follow ${base.path}`);
          }
          const originalSignature = await app.vault.read(paired);
          await app.vault.rename(base, `${folder}/renamed.html`);
          const renamedSignature = app.vault.getFileByPath(`${folder}/renamed.html.p7s`);
          const orphan = await app.saveAttachment('missing.html', 'p7s', new TextEncoder().encode('orphan').buffer);
          return { baseContent: await app.vault.read(base), importedBaseName, originalSignature, orphanName: orphan.name, renamedBaseName: base.name, renamedSignature: renamedSignature?.name };
        } finally {
          leaf.detach();
          await settingsComponent.editAndSave((settings) => {
            Object.assign(settings, previous);
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });
    expect(result.importedBaseName).not.toBe('УХВАЛА.html');
    expect(result.importedBaseName).toMatch(/\.html$/u);
    expect(result.originalSignature).toBe('detached signature bytes');
    expect(result.renamedSignature).toBe('renamed.html.p7s');
    expect(result.renamedBaseName).toBe('renamed.html');
    expect(result.orphanName).toBe('missing.html.p7s');
    expect(result.baseContent).toBe('<html>Document to sign</html>');
  });
});
