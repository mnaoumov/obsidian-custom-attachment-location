/**
 * @file
 *
 * Copies an attachment's original file name from the file menu and from the attachment link's menu.
 *
 * The test runs as several `evalInObsidian` phases sharing one {@link ContextId}, never as one closure. Every wait inside
 * a closure shares the harness's 30-second per-closure cap, and a one-core Android guest under host load spent most of
 * that budget in one step on one run and in another step on the next. One phase per step gives each step its own cap.
 */

import type {
  TFile,
  WorkspaceLeaf
} from 'obsidian';
import type {
  EvalInObsidianParams,
  Lib
} from 'obsidian-integration-testing';

import {
  ContextId,
  evalInObsidian
} from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { PluginSettingsComponentLike } from '../../scripts/helpers/plugin-settings-component-finder.ts';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';
import { waitForPluginSettingsLoaded } from '../../scripts/helpers/plugin-settings-loaded-wait.ts';

interface ClickActionUntilCopiedParams {
  readonly clickElement: Lib['clickElement'];
  readonly dismissMenu: () => Promise<void>;
  readonly findMenuAction: () => HTMLElement;
  readonly isRetryAllowed: boolean;
  readonly menuName: string;
  readonly openMenu: () => Promise<void>;
  readonly state: CopyTestState;
  readonly waitUntil: Lib['waitUntil'];
}

interface CopyTestContext {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- The setup phase stores the state here for the later phases.
  state?: CopyTestState;
}

interface CopyTestState {
  /**
  Each text the clipboard writer finished writing, in order.
  */
  readonly copiedValues: string[];
  /**
  Each imported attachment; the setup phase pushes the one it imports.
  */
  readonly importedFiles: TFile[];
  /**
  Whether the system clipboard round-trips a probe text. A session with no clipboard of its own (a scheduled or
  background launch on Windows) reads back an empty string after a successful write, which says nothing about the plugin.
  */
  readonly isClipboardReadable: boolean;
  readonly leaf: WorkspaceLeaf;
  readonly missing: TFile;
  readonly note: TFile;
  readonly previousClipboard: null | string;
  readonly priorSettings: Settings;
  readonly settingsComponent: PluginSettingsComponentLike<Settings>;
  /**
  Each text the clipboard writer was CALLED with, pushed before the write is awaited.
  */
  readonly startedWrites: string[];
  readonly writeText: Clipboard['writeText'];
}

interface Settings {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  attachmentFolderPath: string;
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  attachmentRenameMode: string;
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  generatedAttachmentFileName: string;
}

/**
 * Opens a menu, clicks its `Copy original file name` action, and waits for the copy to finish.
 *
 * The click and the write are waited for separately. A click that never reached the action leaves the writer uncalled,
 * and on Android, where a trusted tap on a loaded guest can be lost, the menu is opened again and the click is retried
 * once. A write that started but is slow is only waited for, never retried, so the action runs once per delivered click.
 *
 * Runs in the renderer, handed over through `evalInObsidian`'s `input`, so it reaches nothing outside its own body.
 *
 * @param params - The menu to drive and the harness helpers to drive it with.
 * @returns The text the action wrote.
 */
async function clickActionUntilCopied(params: ClickActionUntilCopiedParams): Promise<string> {
  const { clickElement, dismissMenu, findMenuAction, isRetryAllowed, menuName, openMenu, state, waitUntil } = params;
  const startedBefore = state.startedWrites.length;
  const copiedBefore = state.copiedValues.length;
  const maxAttempts = isRetryAllowed ? 2 : 1;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    await openMenu();
    const action = findMenuAction();
    if (action.classList.contains('is-disabled')) {
      throw new Error(`The ${menuName} offers no original name.`);
    }
    await clickElement({ element: action });
    try {
      await waitUntil({
        message: `The ${menuName} did not call the clipboard writer (attempt ${String(attempt)} of ${String(maxAttempts)})`,
        predicate: () => state.startedWrites.length > startedBefore,
        timeoutInMilliseconds: 5000
      });
      break;
    } catch (error) {
      if (attempt === maxAttempts) {
        throw error;
      }
      console.warn(`The ${menuName} click did not reach the action; opening the menu again.`, error);
      await dismissMenu();
    }
  }
  await waitUntil({
    message: `The clipboard write from the ${menuName} did not finish`,
    predicate: () => state.copiedValues.length > copiedBefore,
    timeoutInMilliseconds: 8000
  });
  const copied = state.copiedValues[copiedBefore];
  if (copied === undefined) {
    throw new Error(`The ${menuName} wrote nothing.`);
  }
  return copied;
}

/**
 * Finds the open menu's `Copy original file name` action.
 *
 * Runs in the renderer, handed over through `evalInObsidian`'s `input`, so it reaches nothing outside its own body.
 *
 * @returns The action's menu item.
 */
function findCopyOriginalNameAction(): HTMLElement {
  const title = 'Copy original file name';
  const item = [...document.querySelectorAll<HTMLElement>('.menu-item')].find((candidate) => candidate.querySelector('.menu-item-title')?.textContent === title);
  if (!item) {
    throw new Error(`Missing menu action: ${title}`);
  }
  return item;
}

/**
 * Reads the test's state from the shared context.
 *
 * Runs in the renderer, handed over through `evalInObsidian`'s `input`, so it reaches nothing outside its own body.
 *
 * @param context - The context the setup phase stored the state in.
 * @returns The state.
 */
function getCopyTestState(context: CopyTestContext): CopyTestState {
  if (!context.state) {
    throw new Error('The setup phase stored no state.');
  }
  return context.state;
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

describe('Copy original attachment file name', () => {
  it('copies the imported name to the system clipboard from file and link menus, offers no source path, and disables a missing name', async () => {
    await waitForPluginSettingsLoaded();
    const vaultPath = getTemporaryVault().path;
    const contextId = new ContextId<CopyTestContext>();
    const input = { clickActionUntilCopied, findCopyOriginalNameAction, findPluginSettingsComponent, getCopyTestState, isSettings };

    async function runPhase<Result>(
      phase: string,
      callback: EvalInObsidianParams<typeof input, Result, typeof contextId>['callback']
    ): Promise<Result> {
      try {
        return await evalInObsidian({ callback, contextId, input, vaultPath });
      } catch (error) {
        throw new Error(`Original metadata copy failed during ${phase}: ${String(error)}`, { cause: error });
      }
    }

    let bodyError: unknown;
    try {
      const importedName = await runPhase('setup', async ({ app, context, findPluginSettingsComponent: findSettings, isSettings: isTestSettings, obsidianModule: { Platform } }) => {
        const settingsComponent = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isTestSettings);
        if (!settingsComponent) {
          throw new Error('The plugin settings were not found.');
        }
        const clipboard = navigator.clipboard;
        const stamp = Date.now().toString();
        // Android's clipboard read bridge can reject even though writing is supported; this emulator is owned by the test.
        const previousClipboard = Platform.isDesktopApp ? await clipboard.readText() : null;
        let isClipboardReadable = false;
        if (Platform.isDesktopApp) {
          const probe = `copy-original-probe-${stamp}`;
          await clipboard.writeText(probe);
          isClipboardReadable = await clipboard.readText() === probe;
        }
        const state: CopyTestState = {
          copiedValues: [],
          importedFiles: [],
          isClipboardReadable,
          leaf: app.workspace.getLeaf(false),
          missing: await app.vault.createBinary(`copy-missing-${stamp}.pdf`, new ArrayBuffer(1)),
          note: await app.vault.create(`copy-original-${stamp}.md`, ''),
          previousClipboard,
          priorSettings: { ...settingsComponent.settings },
          settingsComponent,
          startedWrites: [],
          writeText: clipboard.writeText
        };
        context.state = state;
        /*
         * Observe the calls while still invoking the REAL writer, rather than replacing the clipboard. A call is recorded
         * before its write is awaited and again once it finished, so a click that never reached the action is told apart
         * from a slow write. On desktop the system clipboard is then read back, so the assertion covers what a user would
         * paste. Android's read bridge can reject, so there the observed write is the evidence.
         */
        Object.assign(clipboard, {
          async writeText(text: string): Promise<void> {
            state.startedWrites.push(text);
            await state.writeText.call(clipboard, text);
            state.copiedValues.push(text);
          }
        });
        await settingsComponent.editAndSave((draft) => {
          draft.attachmentFolderPath = './';
          draft.attachmentRenameMode = 'All';
          draft.generatedAttachmentFileName = `renamed-${stamp}`;
        });
        await state.leaf.openFile(state.note);
        const files = await app.importAttachments([{
          data: Promise.resolve(new TextEncoder().encode('original document').buffer),
          extension: 'pdf',
          filepath: 'original/source/arrival.pdf',
          name: 'arrival'
        }], null);
        const file = files[0];
        if (!file) {
          throw new Error('The attachment was not imported.');
        }
        state.importedFiles.push(file);
        await app.vault.modify(state.note, `[[${file.path}]]`);
        return file.name;
      });

      const fileMenu = await runPhase(
        'file menu',
        async ({ app, clickActionUntilCopied: clickUntilCopied, context, findCopyOriginalNameAction: findAction, getCopyTestState: getState, lib: { clickElement, waitUntil }, obsidianModule: { Menu, Platform } }) => {
          const state = getState(context);
          const file = state.importedFiles[0];
          if (!file) {
            throw new Error('The setup phase imported nothing.');
          }
          const menus: InstanceType<typeof Menu>[] = [];
          function hideMenus(): void {
            for (const menu of menus.splice(0)) {
              menu.hide();
            }
          }
          const copied = await clickUntilCopied({
            clickElement,
            dismissMenu: async () => {
              hideMenus();
              await sleep(200);
            },
            findMenuAction: findAction,
            isRetryAllowed: !Platform.isDesktopApp,
            menuName: 'file menu',
            openMenu: async () => {
              const menu = new Menu().setUseNativeMenu(false);
              menus.push(menu);
              app.workspace.trigger('file-menu', menu, file, 'file-explorer', state.leaf);
              menu.showAtPosition({ x: 100, y: 100 });
              // Let the menu finish opening before sending a pointer event to its final position.
              await sleep(200);
            },
            state,
            waitUntil
          });
          const clipboard = Platform.isDesktopApp && state.isClipboardReadable ? await navigator.clipboard.readText() : null;
          hideMenus();
          return { clipboard, copied };
        }
      );

      await runPhase('attachment link render', async ({ context, getCopyTestState: getState, lib: { waitUntil }, obsidianModule: { MarkdownView } }) => {
        const state = getState(context);
        await state.leaf.setViewState({ state: { file: state.note.path, mode: 'preview' }, type: 'markdown' });
        const view = state.leaf.view;
        if (!(view instanceof MarkdownView)) {
          throw new TypeError('The note did not open in a markdown view.');
        }
        // A one-core Android guest under host load can take more than 4 s to render Reading view.
        await waitUntil({
          message: 'The attachment link did not render in Reading view',
          predicate: () => view.contentEl.querySelector('a.internal-link') !== null,
          timeoutInMilliseconds: 20_000
        });
      });

      const linkMenu = await runPhase(
        'attachment link menu',
        async ({
          app,
          clickActionUntilCopied: clickUntilCopied,
          context,
          findCopyOriginalNameAction: findAction,
          getCopyTestState: getState,
          lib: { clickElement, pressKey, waitUntil },
          obsidianModule: { Menu, Platform }
        }) => {
          const state = getState(context);
          const file = state.importedFiles[0];
          if (!file) {
            throw new Error('The setup phase imported nothing.');
          }
          const link = state.leaf.view.containerEl.querySelector<HTMLElement>('a.internal-link');
          if (!link) {
            throw new Error('The attachment link is no longer rendered.');
          }
          let hasPathAction = false;
          async function dismissMenu(): Promise<void> {
            if (document.querySelector('.menu')) {
              await pressKey({ key: 'Escape' });
            }
          }
          const copied = await clickUntilCopied({
            clickElement,
            dismissMenu,
            findMenuAction: findAction,
            isRetryAllowed: !Platform.isDesktopApp,
            menuName: 'link menu',
            openMenu: async () => {
              if (Platform.isDesktopApp) {
                await clickElement({ button: 'right', element: link });
              } else {
                /*
                 * On a one-core Android guest the WebView's gesture recognizer takes the trusted long press for a tap,
                 * which follows the link instead of opening its menu. The gesture is the harness's and Android's; what
                 * this test owns is the menu the plugin contributes, so raise the `file-menu` event Obsidian raises for
                 * a link's menu, the way the file menu phase does. Desktop keeps the trusted right click.
                 */
                const rect = link.getBoundingClientRect();
                const menu = new Menu().setUseNativeMenu(false);
                app.workspace.trigger('file-menu', menu, file, 'link-context-menu', state.leaf);
                menu.showAtPosition({ x: rect.left, y: rect.bottom });
              }
              await waitUntil({ message: 'The link menu did not open', predicate: () => document.querySelector('.menu') !== null, timeoutInMilliseconds: 3000 });
              await sleep(200);
              // The import carried a source path; no action may expose it.
              hasPathAction ||= [...document.querySelectorAll('.menu-item-title')].some((title) => title.textContent === 'Copy original path');
            },
            state,
            waitUntil
          });
          const clipboard = Platform.isDesktopApp && state.isClipboardReadable ? await navigator.clipboard.readText() : null;
          await dismissMenu();
          return { clipboard, copied, hasPathAction };
        }
      );

      const missingMenu = await runPhase(
        'missing metadata',
        ({ app, context, findCopyOriginalNameAction: findAction, getCopyTestState: getState, obsidianModule: { Menu, Platform } }) => {
          const state = getState(context);
          const menu = new Menu().setUseNativeMenu(false);
          app.workspace.trigger('file-menu', menu, state.missing, 'file-explorer', state.leaf);
          menu.showAtPosition({ x: 100, y: 100 });
          const isNameActionDisabled = findAction().classList.contains('is-disabled');
          menu.hide();
          return { isClipboardReadable: state.isClipboardReadable, isDesktopApp: Platform.isDesktopApp, isNameActionDisabled };
        }
      );

      expect(fileMenu.copied).toBe('arrival.pdf');
      expect(linkMenu.copied).toBe('arrival.pdf');
      expect(linkMenu.hasPathAction).toBe(false);
      const isReadBackChecked = missingMenu.isDesktopApp && missingMenu.isClipboardReadable;
      if (missingMenu.isDesktopApp && !isReadBackChecked) {
        console.warn('The system clipboard did not round-trip a probe text, so the clipboard read-back was skipped; the observed writes remain the evidence.');
      }
      expect([fileMenu.clipboard, linkMenu.clipboard]).toStrictEqual(
        isReadBackChecked ? ['arrival.pdf', 'arrival.pdf'] : [null, null]
      );
      expect(importedName).toMatch(/^renamed-\d+\.pdf$/);
      expect(missingMenu.isNameActionDisabled).toBe(true);
    } catch (error) {
      bodyError = error;
      throw error;
    } finally {
      await cleanUp().catch((error: unknown) => {
        // A cleanup failure must not replace the failure that actually broke the test.
        if (bodyError === undefined) {
          throw error;
        }
        console.error('Original metadata copy cleanup failed after the test had already failed.', error);
      });
    }

    async function cleanUp(): Promise<void> {
      await runPhase('cleanup', async ({ app, context, lib: { pressKey } }) => {
        const state = context.state;
        if (!state) {
          return;
        }
        const clipboard = navigator.clipboard;
        Object.assign(clipboard, { writeText: state.writeText });
        if (state.previousClipboard !== null) {
          await clipboard.writeText(state.previousClipboard);
        }
        await state.settingsComponent.editAndSave((draft) => {
          Object.assign(draft, state.priorSettings);
        });
        for (const path of [state.note.path, state.missing.path, ...state.importedFiles.map((file) => file.path)]) {
          const file = app.vault.getFileByPath(path);
          if (file) {
            await app.fileManager.trashFile(file);
          }
        }
        if (document.querySelector('.menu')) {
          await pressKey({ key: 'Escape' });
        }
      });
      await contextId.dispose(vaultPath);
    }
  }, 180_000);
});
