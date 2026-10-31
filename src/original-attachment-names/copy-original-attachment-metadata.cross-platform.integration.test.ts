import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

interface CopyOriginalAttachmentMetadataResult {
  readonly disabled: boolean[];
  readonly fileMenuClipboard: null | string;
  readonly fileMenuCopy: string | undefined;
  readonly importedName: string;
  readonly isDesktopApp: boolean;
  readonly linkMenuClipboard: null | string;
  readonly linkMenuCopy: string | undefined;
}

describe('Copy original attachment metadata', () => {
  it('copies exact imported metadata to the system clipboard from file and link menus and disables missing values', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettings, lib: { clickElement, pressKey, waitUntil }, obsidianModule: { MarkdownView, Menu, Platform } }) {
        interface Settings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          generatedAttachmentFileName: string;
        }
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null && 'generatedAttachmentFileName' in value;
        }
        const settings = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
        if (!settings) {
          throw new Error('The plugin settings were not found.');
        }
        const prior = { ...settings.settings };
        const clipboard = navigator.clipboard;
        // Android's clipboard read bridge can reject even though writing is supported; this emulator is owned by the test.
        const previousClipboard = Platform.isDesktopApp ? await clipboard.readText() : null;
        const writeText = clipboard.writeText;
        /*
         * Observe successful calls while still invoking the REAL writer, rather than replacing the clipboard.
         * The observer tells the test when each action's write has finished; on desktop the system clipboard is then
         * read back, so the assertion covers what a user would paste. Android's read bridge can reject, so there the
         * observed write is the evidence.
         */
        const copiedValues: string[] = [];
        async function readSystemClipboard(): Promise<null | string> {
          return Platform.isDesktopApp ? await clipboard.readText() : null;
        }
        Object.assign(clipboard, {
          async writeText(text: string): Promise<void> {
            await writeText.call(clipboard, text);
            copiedValues.push(text);
          }
        });
        const stamp = Date.now().toString();
        const sourcePath = 'original/source/arrival.pdf';
        const note = await app.vault.create(`copy-original-${stamp}.md`, '');
        const missing = await app.vault.createBinary(`copy-missing-${stamp}.pdf`, new ArrayBuffer(1));
        let importedPath = '';
        function findAction(title: string): HTMLElement {
          const item = [...document.querySelectorAll<HTMLElement>('.menu-item')].find((candidate) => candidate.querySelector('.menu-item-title')?.textContent === title);
          if (!item) {
            throw new Error(`Missing menu action: ${title}`);
          }
          return item;
        }
        async function dismissMenu(): Promise<void> {
          if (document.querySelector('.menu')) {
            await pressKey({ key: 'Escape' });
          }
        }
        let bodyError: Error | null = null;
        let cleanupError: Error | null = null;
        let menuResult: CopyOriginalAttachmentMetadataResult | null = null;
        let phase = 'settings';
        try {
          await settings.editAndSave((draft) => {
            draft.attachmentFolderPath = './';
            draft.attachmentRenameMode = 'All';
            draft.generatedAttachmentFileName = `renamed-${stamp}`;
          });
          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);
          phase = 'attachment import';
          const files = await app.importAttachments([{
            data: Promise.resolve(new TextEncoder().encode('original document').buffer),
            extension: 'pdf',
            filepath: sourcePath,
            name: 'arrival'
          }], null);
          const file = files[0];
          if (!file) {
            throw new Error('The attachment was not imported.');
          }
          importedPath = file.path;
          await app.vault.modify(note, `[[${file.path}]]`);
          phase = 'file menu';
          const menu = new Menu().setUseNativeMenu(false);
          app.workspace.trigger('file-menu', menu, file, 'file-explorer', leaf);
          menu.showAtPosition({ x: 100, y: 100 });
          // Let the menu finish opening before sending a pointer event to its final position.
          await sleep(200);
          const nameAction = findAction('Copy original file name');
          if (nameAction.classList.contains('is-disabled')) {
            throw new Error(`Original name is missing for ${file.path}`);
          }
          await clickElement({ element: nameAction });
          await waitUntil({ message: 'The file menu did not call the clipboard writer', predicate: () => copiedValues.length === 1, timeoutInMilliseconds: 3000 });
          const fileMenuCopy = copiedValues[0];
          const fileMenuClipboard = await readSystemClipboard();
          menu.hide();

          phase = 'attachment link menu';
          await leaf.setViewState({ state: { file: note.path, mode: 'preview' }, type: 'markdown' });
          const view = leaf.view;
          if (!(view instanceof MarkdownView)) {
            throw new TypeError('The note did not open in a markdown view.');
          }
          await waitUntil({ predicate: () => view.contentEl.querySelector('a.internal-link') !== null, timeoutInMilliseconds: 4000 });
          const link = view.contentEl.querySelector<HTMLElement>('a.internal-link');
          if (!link) {
            throw new Error('The attachment link did not render.');
          }
          await clickElement({ button: 'right', element: link });
          await waitUntil({ predicate: () => document.querySelector('.menu') !== null, timeoutInMilliseconds: 3000 });
          await sleep(200);
          await clickElement({ element: findAction('Copy original path') });
          await waitUntil({ message: 'The link menu did not call the clipboard writer', predicate: () => copiedValues.length === 2, timeoutInMilliseconds: 3000 });
          const linkMenuCopy = copiedValues[1];
          const linkMenuClipboard = await readSystemClipboard();
          await dismissMenu();

          phase = 'missing metadata';
          const missingMenu = new Menu().setUseNativeMenu(false);
          app.workspace.trigger('file-menu', missingMenu, missing, 'file-explorer', leaf);
          missingMenu.showAtPosition({ x: 100, y: 100 });
          const disabled = ['Copy original file name', 'Copy original path'].map((title) => findAction(title).classList.contains('is-disabled'));
          missingMenu.hide();
          menuResult = { disabled, fileMenuClipboard, fileMenuCopy, importedName: file.name, isDesktopApp: Platform.isDesktopApp, linkMenuClipboard, linkMenuCopy };
        } catch (error) {
          bodyError = new Error(`Original metadata copy failed during ${phase}: ${String(error)}`, { cause: error });
        } finally {
          Object.assign(clipboard, { writeText });
          try {
            if (previousClipboard !== null) {
              await clipboard.writeText(previousClipboard);
            }
            await settings.editAndSave((draft) => {
              Object.assign(draft, prior);
            });
            for (const path of [note.path, missing.path, importedPath]) {
              const file = app.vault.getFileByPath(path);
              if (file) {
                await app.fileManager.trashFile(file);
              }
            }
            await dismissMenu();
          } catch (error) {
            cleanupError = new Error(`Original metadata copy cleanup failed: ${String(error)}`, { cause: error });
          }
        }
        if (bodyError) {
          throw bodyError;
        }
        if (cleanupError) {
          throw cleanupError;
        }
        if (!menuResult) {
          throw new Error('The menu test produced no result.');
        }
        return menuResult;
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });
    expect(result.fileMenuCopy).toBe('arrival.pdf');
    expect(result.linkMenuCopy).toBe('original/source/arrival.pdf');
    expect([result.fileMenuClipboard, result.linkMenuClipboard]).toStrictEqual(
      result.isDesktopApp ? ['arrival.pdf', 'original/source/arrival.pdf'] : [null, null]
    );
    expect(result.importedName).toMatch(/^renamed-\d+\.pdf$/);
    expect(result.disabled).toStrictEqual([true, true]);
  });
});
