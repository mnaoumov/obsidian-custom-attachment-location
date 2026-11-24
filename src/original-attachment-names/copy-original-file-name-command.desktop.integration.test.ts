/**
 * @file
 *
 * Runs `Copy original file name` through Obsidian's command registry, the way a hotkey does: on the attachment link
 * under the cursor in a note's editor, and on the open attachment itself. It also checks that the command is not
 * offered while the cursor is on plain text.
 *
 * The copies go to the harness's in-memory clipboard, never the system one: the harness window is hidden and
 * unfocused, so Chromium can refuse the system clipboard.
 */

import type { TFile } from 'obsidian';

import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';
import { waitForPluginSettingsLoaded } from '../../scripts/helpers/plugin-settings-loaded-wait.ts';

interface Settings {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Edited through editAndSave.
  attachmentFolderPath: string;
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Edited through editAndSave.
  attachmentRenameMode: string;
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Edited through editAndSave.
  generatedAttachmentFileName: string;
}

/**
 * Checks that a value carries the settings the test edits.
 *
 * Runs in the renderer, handed over through `evalInObsidian`'s `input`, so it reaches nothing outside its own body.
 *
 * @param value - The value to check.
 * @returns Whether the value carries the settings.
 */
function isSettings(value: unknown): value is Settings {
  return typeof value === 'object' && value !== null && 'generatedAttachmentFileName' in value;
}

describe('Copy original file name command', () => {
  it('copies the original name of the linked attachment under the cursor and of the open attachment, and is not offered on plain text', async () => {
    await waitForPluginSettingsLoaded();
    const result = await evalInObsidian({
      callback: async ({ app, findPluginSettingsComponent: findSettings, isSettings: isTestSettings, lib: { useInMemoryClipboard, waitUntil }, obsidianModule: { MarkdownView } }) => {
        const commandId = 'obsidian-custom-attachment-location:copy-original-file-name';
        // `executeCommandById` reports only that the command exists, so availability is asked the way the command
        // palette and the hotkey manager ask it: through the command's own check.
        function isOffered(): boolean {
          return app.commands.findCommand(commandId)?.checkCallback?.(true) === true;
        }
        const settingsComponent = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isTestSettings);
        if (!settingsComponent) {
          throw new Error('The plugin settings were not found.');
        }
        const { attachmentFolderPath, attachmentRenameMode, generatedAttachmentFileName } = settingsComponent.settings;
        const stamp = Date.now().toString();
        const clipboard = useInMemoryClipboard();
        const createdFiles: TFile[] = [];
        try {
          await settingsComponent.editAndSave((draft) => {
            draft.attachmentFolderPath = './';
            draft.attachmentRenameMode = 'All';
            draft.generatedAttachmentFileName = `copied-${stamp}`;
          });
          const note = await app.vault.create(`copy-command-${stamp}.md`, '');
          createdFiles.push(note);
          const leaf = app.workspace.getLeaf(true);
          await leaf.openFile(note);
          const files = await app.importAttachments([{
            data: Promise.resolve(new TextEncoder().encode('original document').buffer),
            extension: 'pdf',
            filepath: 'original/source/arrival.pdf',
            name: 'arrival'
          }], null);
          const attachment = files[0];
          if (!attachment) {
            throw new Error('The attachment was not imported.');
          }
          createdFiles.push(attachment);
          await app.vault.modify(note, `plain text\n![[${attachment.name}]]`);
          await leaf.setViewState({ active: true, state: { file: note.path, mode: 'source' }, type: 'markdown' });
          const view = leaf.view;
          if (!(view instanceof MarkdownView)) {
            throw new TypeError('The note did not open in a markdown view.');
          }
          app.workspace.setActiveLeaf(leaf, { focus: true });
          await waitUntil({ message: 'The editor did not load the note', predicate: () => view.editor.lineCount() === 2 });

          view.editor.setCursor({ ch: 3, line: 0 });
          const isOfferedOnPlainText = isOffered();

          view.editor.setCursor({ ch: 0, line: 1 });
          const copiedBefore = clipboard.writtenTexts.length;
          const isOfferedOnLink = isOffered();
          app.commands.executeCommandById(commandId);
          await waitUntil({ message: 'The command on the link copied nothing', predicate: () => clipboard.writtenTexts.length > copiedBefore });
          const copiedFromLink = clipboard.writtenTexts.at(-1);

          await leaf.openFile(attachment);
          await waitUntil({ message: 'The attachment did not become the active file', predicate: () => app.workspace.getActiveFile() === attachment });
          const copiedBeforeOpen = clipboard.writtenTexts.length;
          const isOfferedOnOpenAttachment = isOffered();
          app.commands.executeCommandById(commandId);
          await waitUntil({ message: 'The command on the open attachment copied nothing', predicate: () => clipboard.writtenTexts.length > copiedBeforeOpen });
          const copiedFromOpenAttachment = clipboard.writtenTexts.at(-1);
          leaf.detach();

          return { attachmentName: attachment.name, copiedFromLink, copiedFromOpenAttachment, isOfferedOnLink, isOfferedOnOpenAttachment, isOfferedOnPlainText };
        } finally {
          clipboard.restore();
          await settingsComponent.editAndSave((draft) => {
            Object.assign(draft, { attachmentFolderPath, attachmentRenameMode, generatedAttachmentFileName });
          });
          for (const file of createdFiles) {
            await app.fileManager.trashFile(file);
          }
        }
      },
      input: { findPluginSettingsComponent, isSettings },
      vaultPath: getTemporaryVault().path
    });

    expect(result.attachmentName).toMatch(/^copied-\d+\.pdf$/);
    expect(result.isOfferedOnPlainText).toBe(false);
    expect(result.isOfferedOnLink).toBe(true);
    expect(result.copiedFromLink).toBe('arrival.pdf');
    expect(result.isOfferedOnOpenAttachment).toBe(true);
    expect(result.copiedFromOpenAttachment).toBe('arrival.pdf');
  }, 120_000);
});
