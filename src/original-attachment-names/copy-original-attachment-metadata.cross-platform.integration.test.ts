/**
 * @file
 *
 * Copies an attachment's original file name from the file menu and from the attachment link's menu.
 *
 * The test runs as several `evalInObsidian` phases sharing one {@link ContextId}, never as one closure. Every wait inside
 * a closure shares the harness's 30-second per-closure cap, and a one-core Android guest under host load spent most of
 * that budget in one step on one run and in another step on the next. One phase per step gives each step its own cap.
 *
 * The state the phases share lives in the page, and Android can recreate its WebView between two phases: the harness
 * logs `Eval found ChromeDriver's window closed; re-attaching the WebView`, the page reloads, and the next phase finds
 * no state. So everything cleanup needs (the settings to restore, the stamp in every file name the test creates) is
 * kept on the Node side, and a phase that finds the state gone starts the flow again from setup, once.
 *
 * The copies go to the harness's in-memory clipboard, never the system one. The harness window is hidden and unfocused,
 * so Chromium can refuse the system clipboard, and that clipboard is shared with whoever else uses the machine.
 */

import type {
  TFile,
  WorkspaceLeaf
} from 'obsidian';
import type {
  EvalInObsidianParams,
  InMemoryClipboard,
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

/**
 * How many times the flow runs from setup when a phase finds the page state gone.
 */
const MAX_FLOW_ATTEMPTS = 2;

/**
 * The start of the error {@link getCopyTestState} throws when the page state is gone.
 */
const STATE_LOST_MARKER = 'The page lost the test state';

/**
 * What the test keeps on the Node side, so a page reload loses none of it. Handed to every phase through `input`.
 */
interface CarriedState {
  /**
  The settings the test edits, as they were before it; `null` until the snapshot phase ran.
  */
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Filled by the snapshot phase.
  priorSettings: null | Settings;
  /**
  The stamp of the current attempt, in the name of every file it creates.
  */
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Each attempt sets its own.
  stamp: string;
  /**
  The stamp of every attempt so far, so cleanup finds the files of an attempt whose page state was lost.
  */
  readonly stamps: string[];
}

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
  The in-memory clipboard the setup phase installed; its `writtenTexts` lists every copy, in order.
  */
  readonly clipboard: InMemoryClipboard;
  /**
  Each imported attachment; the setup phase pushes the one it imports.
  */
  readonly importedFiles: TFile[];
  readonly leaf: WorkspaceLeaf;
  readonly missing: TFile;
  readonly note: TFile;
  readonly settingsComponent: PluginSettingsComponentLike<Settings>;
}

interface FlowResult {
  readonly fileMenu: MenuCopyResult;
  readonly importedName: string;
  readonly linkMenu: LinkMenuCopyResult;
  readonly missingMenu: MissingMenuResult;
}

interface LinkMenuCopyResult extends MenuCopyResult {
  readonly hasPathAction: boolean;
}

interface MenuCopyResult {
  /**
  What the clipboard holds after the copy, which is what a paste would insert.
  */
  readonly clipboard: string;
  readonly copied: string;
}

interface MissingMenuResult {
  readonly isNameActionDisabled: boolean;
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
 * A click that never reached the action writes nothing to the clipboard, and on Android, where a trusted tap on a
 * loaded guest can be lost, the menu is opened again and the click is retried once. The in-memory clipboard records a
 * write as soon as it is made, so a write that arrived is never retried and the action runs once per delivered click.
 *
 * Runs in the renderer, handed over through `evalInObsidian`'s `input`, so it reaches nothing outside its own body.
 *
 * @param params - The menu to drive and the harness helpers to drive it with.
 * @returns The text the action wrote.
 */
async function clickActionUntilCopied(params: ClickActionUntilCopiedParams): Promise<string> {
  const { clickElement, dismissMenu, findMenuAction, isRetryAllowed, menuName, openMenu, state, waitUntil } = params;
  const copiedBefore = state.clipboard.writtenTexts.length;
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
        message: `The ${menuName} wrote nothing to the clipboard (attempt ${String(attempt)} of ${String(maxAttempts)})`,
        predicate: () => state.clipboard.writtenTexts.length > copiedBefore,
        timeoutInMilliseconds: 8000
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
  const copied = state.clipboard.writtenTexts[copiedBefore];
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
  /*
   * A long press that opened its menu late can leave a second menu under the newest one, which covers its items. Only the
   * newest menu, the last in the DOM, is on top, so a tap on another menu's item would land on the newest one.
   */
  const menu = [...document.querySelectorAll<HTMLElement>('.menu')].at(-1);
  const item = [...(menu?.querySelectorAll<HTMLElement>('.menu-item') ?? [])].find((candidate) => candidate.querySelector('.menu-item-title')?.textContent === title);
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
    // `STATE_LOST_MARKER` on the Node side matches this text; a serialized closure cannot read that constant.
    throw new Error('The page lost the test state: the setup phase stored none, or the WebView reloaded since.');
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
  it('copies the imported name to the clipboard from file and link menus, offers no source path, and disables a missing name', async () => {
    await waitForPluginSettingsLoaded();
    const vaultPath = getTemporaryVault().path;
    let contextId = new ContextId<CopyTestContext>();
    const carried: CarriedState = { priorSettings: null, stamp: '', stamps: [] };
    const input = { carried, clickActionUntilCopied, findCopyOriginalNameAction, findPluginSettingsComponent, getCopyTestState, isSettings };

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
      carried.priorSettings = await runPhase('snapshot', ({ app, findPluginSettingsComponent: findSettings, isSettings: isTestSettings }) => {
        const settingsComponent = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isTestSettings);
        if (!settingsComponent) {
          throw new Error('The plugin settings were not found.');
        }
        const { attachmentFolderPath, attachmentRenameMode, generatedAttachmentFileName } = settingsComponent.settings;
        return { attachmentFolderPath, attachmentRenameMode, generatedAttachmentFileName };
      });

      let flow: FlowResult | undefined;
      for (let attempt = 1; flow === undefined; attempt++) {
        carried.stamp = `${Date.now().toString()}${String(attempt)}`;
        carried.stamps.push(carried.stamp);
        try {
          flow = await runFlow();
        } catch (error) {
          if (attempt >= MAX_FLOW_ATTEMPTS || !String(error).includes(STATE_LOST_MARKER)) {
            throw error;
          }
          console.warn(`The page lost the test state (attempt ${String(attempt)} of ${String(MAX_FLOW_ATTEMPTS)}), most likely a WebView reload; starting again from setup.`, error);
          contextId = new ContextId<CopyTestContext>();
          await waitForPluginSettingsLoaded();
        }
      }
      const { fileMenu, importedName, linkMenu, missingMenu } = flow;

      expect(fileMenu.copied).toBe('arrival.pdf');
      expect(linkMenu.copied).toBe('arrival.pdf');
      expect(linkMenu.hasPathAction).toBe(false);
      expect([fileMenu.clipboard, linkMenu.clipboard]).toStrictEqual(['arrival.pdf', 'arrival.pdf']);
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

    async function runFlow(): Promise<FlowResult> {
      const importedName = await runPhase('setup', async ({ app, carried: { stamp }, context, findPluginSettingsComponent: findSettings, isSettings: isTestSettings, lib: { useInMemoryClipboard } }) => {
        const settingsComponent = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isTestSettings);
        if (!settingsComponent) {
          throw new Error('The plugin settings were not found.');
        }
        // The cleanup phase restores it; installing it again on a retried flow restores the previous one first.
        const clipboard = useInMemoryClipboard();
        const state: CopyTestState = {
          clipboard,
          importedFiles: [],
          leaf: app.workspace.getLeaf(false),
          missing: await app.vault.createBinary(`copy-missing-${stamp}.pdf`, new ArrayBuffer(1)),
          note: await app.vault.create(`copy-original-${stamp}.md`, ''),
          settingsComponent
        };
        context.state = state;
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
          hideMenus();
          return { clipboard: state.clipboard.text, copied };
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
          clickActionUntilCopied: clickUntilCopied,
          context,
          findCopyOriginalNameAction: findAction,
          getCopyTestState: getState,
          lib: { clickElement, pressKey, waitUntil },
          obsidianModule: { Platform }
        }) => {
          const state = getState(context);
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
              /*
               * On Android this is a trusted long press, which the harness presses again when the WebView misreads it as a
               * tap, and which it fails when no `contextmenu` follows at all. Under host load a `contextmenu` can still
               * arrive and open no menu, so the press is repeated here, and each attempt records where its `contextmenu`
               * landed so a final failure says whether it reached the link.
               */
              const maxPresses = Platform.isDesktopApp ? 1 : 3;
              const outcomes: string[] = [];
              for (let press = 1; press <= maxPresses; press++) {
                const targets: string[] = [];
                // A nested function does not keep the narrowing of `link`, so it reads this narrowed copy.
                const linkElement: HTMLElement = link;
                function recordContextMenu($event: MouseEvent): void {
                  const target = $event.target;
                  const where = target instanceof Element
                    ? `${[target.tagName.toLowerCase(), ...target.classList].join('.')}${linkElement.contains(target) ? ' (the link)' : ''}`
                    : target?.constructor.name ?? 'no target';
                  targets.push(`${where} at (${String($event.clientX)}, ${String($event.clientY)})${$event.defaultPrevented ? ', default prevented' : ''}`);
                }
                window.addEventListener('contextmenu', recordContextMenu);
                try {
                  await clickElement({ button: 'right', element: link });
                  // A one-core Android guest under host load can take more than 3 s to open the menu after a long press.
                  await waitUntil({ message: 'The link menu did not open', predicate: () => document.querySelector('.menu') !== null, timeoutInMilliseconds: 10_000 });
                  break;
                } catch (error) {
                  const rect = link.getBoundingClientRect();
                  outcomes.push(
                    `press ${String(press)}: ${String(error)}; contextmenu ${targets.length === 0 ? 'not seen in bubbling' : `on ${targets.join(', ')}`}; link at (${String(Math.round(rect.left))}, ${String(Math.round(rect.top))}) ${String(Math.round(rect.width))}x${String(Math.round(rect.height))}`
                  );
                  if (press === maxPresses) {
                    throw new Error(`The link menu did not open after ${String(maxPresses)} long press(es): ${outcomes.join(' | ')}`, { cause: error });
                  }
                  console.warn(`The link long press opened no menu (press ${String(press)} of ${String(maxPresses)}); pressing again.`, outcomes.at(-1));
                  await sleep(500);
                  // A menu this press opened after the wait gave up would sit under the next press's menu.
                  await dismissMenu();
                } finally {
                  window.removeEventListener('contextmenu', recordContextMenu);
                }
              }
              await sleep(200);
              // The import carried a source path; no action may expose it.
              hasPathAction ||= [...document.querySelectorAll('.menu-item-title')].some((title) => title.textContent === 'Copy original path');
            },
            state,
            waitUntil
          });
          await dismissMenu();
          return { clipboard: state.clipboard.text, copied, hasPathAction };
        }
      );

      const missingMenu = await runPhase(
        'missing metadata',
        ({ app, context, findCopyOriginalNameAction: findAction, getCopyTestState: getState, obsidianModule: { Menu } }) => {
          const state = getState(context);
          const menu = new Menu().setUseNativeMenu(false);
          app.workspace.trigger('file-menu', menu, state.missing, 'file-explorer', state.leaf);
          menu.showAtPosition({ x: 100, y: 100 });
          const isNameActionDisabled = findAction().classList.contains('is-disabled');
          menu.hide();
          return { isNameActionDisabled };
        }
      );

      return { fileMenu, importedName, linkMenu, missingMenu };
    }

    async function cleanUp(): Promise<void> {
      await runPhase('cleanup', async ({ app, carried: { priorSettings, stamps }, findPluginSettingsComponent: findSettings, isSettings: isTestSettings, lib: { getInMemoryClipboard, pressKey } }) => {
        // Looked up rather than read from the page state, which a WebView reload loses while the clipboard may remain.
        getInMemoryClipboard()?.restore();
        if (priorSettings) {
          const settingsComponent = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isTestSettings);
          if (!settingsComponent) {
            throw new Error('The plugin settings were not found, so the edited settings could not be restored.');
          }
          await settingsComponent.editAndSave((draft) => {
            Object.assign(draft, priorSettings);
          });
        }
        // Every file an attempt creates carries its stamp: the note, the missing-name file and the renamed import.
        for (const file of app.vault.getFiles()) {
          if (stamps.some((stamp) => file.basename.includes(stamp))) {
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
