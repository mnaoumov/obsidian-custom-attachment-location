import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for "Only pasted images" telling a screenshot tool's file apart from a real file.
 *
 * Some screenshot tools (PixPin with "Copy images as files", the Windows 11 Snipping Tool) put the capture on the
 * clipboard as a FILE. Obsidian keeps a pasted file's name, so the plugin decides from the gesture and the file
 * itself. By default every pasted file is renamed and anything dragged in keeps its name. With
 * shouldKeepNamesOfPastedNonScreenshotFiles on, a paste of a file on a screenshot path, or written moments ago, is
 * renamed, and an old file elsewhere keeps its name.
 *
 * Why the paste and the drop are DISPATCHED rather than typed: a trusted paste would have to put a file on the
 * system clipboard, which belongs to the user, and a trusted drop needs an OS drag from another application. Neither
 * can be produced from inside Obsidian. A dispatched `ClipboardEvent` / `DragEvent` still runs Obsidian's real
 * handlers end to end (CodeMirror's paste hook, the clipboard manager's drop handler, `insertFiles`,
 * `saveAttachment`), which is the path under test. The file carries its disk path through the `path` property this
 * plugin's `webUtils.getPathForFile` patch reads.
 */

interface AdapterWithFsPromises {
  readonly fsPromises: FsPromisesLike;
}

interface EditorLike {
  readonly cm?: EditorViewLike;
}

interface EditorViewLike {
  readonly contentDOM: HTMLElement;
}

interface FsPromisesLike {
  readonly mkdir: (path: string, options: MkdirOptions) => Promise<unknown>;
  readonly rm: (path: string, options: RmOptions) => Promise<void>;
  readonly utimes: (path: string, atime: Date, mtime: Date) => Promise<void>;
  readonly writeFile: (path: string, data: Uint8Array) => Promise<void>;
}

interface MarkdownViewLike {
  readonly editor?: EditorLike;
}

interface MkdirOptions {
  readonly recursive: boolean;
}

interface OsModuleLike {
  readonly tmpdir: () => string;
}

interface PathModuleLike {
  readonly join: (...parts: string[]) => string;
}

interface RmOptions {
  readonly force: boolean;
  readonly recursive: boolean;
}

interface ScenarioResult {
  readonly isOriginalNameKept: boolean;
  readonly isRenamed: boolean;
  readonly name: string;
}

interface ScreenshotPasteResult {
  readonly error: string;
  readonly scenarios: readonly ScenarioResult[];
  readonly settingsFound: boolean;
}

describe('Only pasted images tells a screenshot tool\'s file apart from a real file', () => {
  it('renames pasted screenshot files and keeps the names of real files and dropped files', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, lib: { waitUntil } }): Promise<ScreenshotPasteResult> {
        interface ScreenshotSettings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          generatedAttachmentFileName: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          screenshotFilePaths: string[];
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldKeepNamesOfPastedNonScreenshotFiles: boolean;
        }

        interface Scenario {
          readonly gesture: 'drop' | 'paste';
          readonly isFresh: boolean;
          readonly name: string;
          readonly screenshotFilePaths: 'folder' | 'none';
          readonly shouldKeepNamesOfPastedNonScreenshotFiles: boolean;
        }

        function isScreenshotSettings(value: unknown): value is ScreenshotSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentRenameMode'] === 'string'
            && Array.isArray((value as Record<string, unknown>)['screenshotFilePaths']);
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isScreenshotSettings);
        if (!settingsComponent) {
          return { error: '', scenarios: [], settingsFound: false };
        }

        // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
        const os = require('node:os') as OsModuleLike;
        // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
        const nodePath = require('node:path') as PathModuleLike;
        const adapterUnknown: unknown = app.vault.adapter;
        const fsPromises = (adapterUnknown as AdapterWithFsPromises).fsPromises;
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const sourceFolderPath = nodePath.join(os.tmpdir(), `custom-attachment-location-screenshot-source-${stamp}`);
        await fsPromises.mkdir(sourceFolderPath, { recursive: true });

        const prior = { ...settingsComponent.settings, screenshotFilePaths: [...settingsComponent.settings.screenshotFilePaths] };
        const scenarios: Scenario[] = [
          // The default: a capture from a tool no list names is renamed however old its file is (issue #97).
          { gesture: 'paste', isFresh: false, name: 'old-file-paste-by-default', screenshotFilePaths: 'none', shouldKeepNamesOfPastedNonScreenshotFiles: false },
          { gesture: 'drop', isFresh: true, name: 'fresh-file-drop-by-default', screenshotFilePaths: 'none', shouldKeepNamesOfPastedNonScreenshotFiles: false },
          { gesture: 'paste', isFresh: false, name: 'old-real-file-paste', screenshotFilePaths: 'none', shouldKeepNamesOfPastedNonScreenshotFiles: true },
          { gesture: 'paste', isFresh: false, name: 'old-screenshot-folder-paste', screenshotFilePaths: 'folder', shouldKeepNamesOfPastedNonScreenshotFiles: true },
          { gesture: 'paste', isFresh: true, name: 'fresh-file-paste', screenshotFilePaths: 'none', shouldKeepNamesOfPastedNonScreenshotFiles: true },
          { gesture: 'drop', isFresh: true, name: 'fresh-screenshot-folder-drop', screenshotFilePaths: 'folder', shouldKeepNamesOfPastedNonScreenshotFiles: true }
        ];
        const results: ScenarioResult[] = [];

        try {
          for (const scenario of scenarios) {
            await settingsComponent.editAndSave((settings) => {
              settings.attachmentRenameMode = 'Only pasted images';
              settings.attachmentFolderPath = './';
              settings.generatedAttachmentFileName = `renamed-${scenario.name}-{{date:{momentJsFormat:'YYYYMMDDHHmmssSSS'}}}`;
              settings.screenshotFilePaths = scenario.screenshotFilePaths === 'folder' ? [sourceFolderPath] : [];
              settings.shouldKeepNamesOfPastedNonScreenshotFiles = scenario.shouldKeepNamesOfPastedNonScreenshotFiles;
            });

            const originalBaseName = `original-${scenario.name}-${stamp}`;
            const sourceFilePath = nodePath.join(sourceFolderPath, `${originalBaseName}.png`);
            const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
            await fsPromises.writeFile(sourceFilePath, bytes);
            if (!scenario.isFresh) {
              const anHourAgo = new Date(Date.now() - 3_600_000);
              await fsPromises.utimes(sourceFilePath, anHourAgo, anHourAgo);
            }

            const note = await app.vault.create(`screenshot-note-${scenario.name}-${stamp}.md`, '');
            const leaf = app.workspace.getLeaf(true);
            await leaf.openFile(note);
            await app.workspace.revealLeaf(leaf);
            app.workspace.setActiveLeaf(leaf, { focus: true });
            await sleep(500);

            const viewUnknown: unknown = leaf.view;
            const contentDom = (viewUnknown as MarkdownViewLike).editor?.cm?.contentDOM;
            if (!contentDom) {
              return { error: 'no editor content DOM', scenarios: results, settingsFound: true };
            }
            contentDom.focus();

            const file = new File([bytes], `${originalBaseName}.png`, { type: 'image/png' });
            Object.defineProperty(file, 'path', { value: sourceFilePath });
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(file);

            if (scenario.gesture === 'paste') {
              contentDom.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: dataTransfer }));
            } else {
              const rect = contentDom.getBoundingClientRect();
              // eslint-disable-next-line obsidian-dev-toolkit/no-untrusted-input-events -- `sendInputEvent` cannot express a drag; the wait below fails unless Obsidian really saved the dropped file.
              contentDom.dispatchEvent(
                new DragEvent('drop', {
                  bubbles: true,
                  cancelable: true,
                  clientX: rect.left + 5,
                  clientY: rect.top + 5,
                  dataTransfer
                })
              );
            }

            const renamedPattern = new RegExp(String.raw`renamed-${scenario.name}-\d+\.png$`);
            let isRenamed = false;
            let isOriginalNameKept = false;
            const SAVE_TIMEOUT_IN_MILLISECONDS = 10_000;
            await waitUntil({
              message: `the attachment of ${scenario.name} to be saved`,
              predicate: () => {
                const paths = app.vault.getFiles().map((vaultFile) => vaultFile.path);
                isRenamed = paths.some((path) => renamedPattern.test(path));
                isOriginalNameKept = paths.some((path) => path.endsWith(`${originalBaseName}.png`));
                return isRenamed || isOriginalNameKept;
              },
              timeoutInMilliseconds: SAVE_TIMEOUT_IN_MILLISECONDS
            });

            results.push({ isOriginalNameKept, isRenamed, name: scenario.name });
            leaf.detach();
          }

          return { error: '', scenarios: results, settingsFound: true };
        } catch (error) {
          return { error: String(error), scenarios: results, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentRenameMode = prior.attachmentRenameMode;
            settings.attachmentFolderPath = prior.attachmentFolderPath;
            settings.generatedAttachmentFileName = prior.generatedAttachmentFileName;
            settings.screenshotFilePaths = prior.screenshotFilePaths;
            settings.shouldKeepNamesOfPastedNonScreenshotFiles = prior.shouldKeepNamesOfPastedNonScreenshotFiles;
          });
          await fsPromises.rm(sourceFolderPath, { force: true, recursive: true }).catch(() => {
            // Best-effort temp cleanup.
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.error).toBe('');
    expect(result.scenarios).toEqual([
      { isOriginalNameKept: false, isRenamed: true, name: 'old-file-paste-by-default' },
      { isOriginalNameKept: true, isRenamed: false, name: 'fresh-file-drop-by-default' },
      { isOriginalNameKept: true, isRenamed: false, name: 'old-real-file-paste' },
      { isOriginalNameKept: false, isRenamed: true, name: 'old-screenshot-folder-paste' },
      { isOriginalNameKept: false, isRenamed: true, name: 'fresh-file-paste' },
      { isOriginalNameKept: true, isRenamed: false, name: 'fresh-screenshot-folder-drop' }
    ]);
  }, 120_000);

  it('renames a screenshot file pasted into a canvas', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, lib: { waitUntil } }): Promise<ScreenshotPasteResult> {
        interface CanvasLike {
          readonly wrapperEl: HTMLElement;
        }

        interface CanvasViewLike {
          readonly canvas?: CanvasLike;
        }

        interface ScreenshotSettings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          generatedAttachmentFileName: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          screenshotFilePaths: string[];
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldKeepNamesOfPastedNonScreenshotFiles: boolean;
        }

        function isScreenshotSettings(value: unknown): value is ScreenshotSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentRenameMode'] === 'string'
            && Array.isArray((value as Record<string, unknown>)['screenshotFilePaths']);
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isScreenshotSettings);
        if (!settingsComponent) {
          return { error: '', scenarios: [], settingsFound: false };
        }

        // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
        const os = require('node:os') as OsModuleLike;
        // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
        const nodePath = require('node:path') as PathModuleLike;
        const adapterUnknown: unknown = app.vault.adapter;
        const fsPromises = (adapterUnknown as AdapterWithFsPromises).fsPromises;
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const sourceFolderPath = nodePath.join(os.tmpdir(), `custom-attachment-location-canvas-screenshot-source-${stamp}`);
        await fsPromises.mkdir(sourceFolderPath, { recursive: true });
        const prior = { ...settingsComponent.settings, screenshotFilePaths: [...settingsComponent.settings.screenshotFilePaths] };

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentRenameMode = 'Only pasted images';
            settings.attachmentFolderPath = './';
            settings.generatedAttachmentFileName = 'renamed-canvas-paste-{{date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}}';
            settings.screenshotFilePaths = [sourceFolderPath];
            settings.shouldKeepNamesOfPastedNonScreenshotFiles = true;
          });

          // An hour old, so only the screenshot folder can make it count as pasted.
          const originalBaseName = `original-canvas-paste-${stamp}`;
          const sourceFilePath = nodePath.join(sourceFolderPath, `${originalBaseName}.png`);
          const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
          await fsPromises.writeFile(sourceFilePath, bytes);
          const anHourAgo = new Date(Date.now() - 3_600_000);
          await fsPromises.utimes(sourceFilePath, anHourAgo, anHourAgo);

          const canvasFile = await app.vault.create(`screenshot-canvas-${stamp}.canvas`, '{"nodes":[],"edges":[]}');
          const leaf = app.workspace.getLeaf(true);
          await leaf.openFile(canvasFile);
          await app.workspace.revealLeaf(leaf);
          app.workspace.setActiveLeaf(leaf, { focus: true });

          const viewUnknown: unknown = leaf.view;
          const CANVAS_TIMEOUT_IN_MILLISECONDS = 10_000;
          await waitUntil({
            message: 'the canvas to render',
            predicate: () => Boolean((viewUnknown as CanvasViewLike).canvas?.wrapperEl),
            timeoutInMilliseconds: CANVAS_TIMEOUT_IN_MILLISECONDS
          });
          const wrapperEl = (viewUnknown as CanvasViewLike).canvas?.wrapperEl;
          if (!wrapperEl) {
            return { error: 'no canvas wrapper', scenarios: [], settingsFound: true };
          }
          // The canvas only takes a paste while its wrapper has the focus.
          wrapperEl.focus();

          const file = new File([bytes], `${originalBaseName}.png`, { type: 'image/png' });
          Object.defineProperty(file, 'path', { value: sourceFilePath });
          const dataTransfer = new DataTransfer();
          dataTransfer.items.add(file);
          wrapperEl.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: dataTransfer }));

          let isRenamed = false;
          let isOriginalNameKept = false;
          const SAVE_TIMEOUT_IN_MILLISECONDS = 10_000;
          await waitUntil({
            message: 'the attachment pasted into the canvas to be saved',
            predicate: () => {
              const paths = app.vault.getFiles().map((vaultFile) => vaultFile.path);
              isRenamed = paths.some((path) => /renamed-canvas-paste-\d+\.png$/.test(path));
              isOriginalNameKept = paths.some((path) => path.endsWith(`${originalBaseName}.png`));
              return isRenamed || isOriginalNameKept;
            },
            timeoutInMilliseconds: SAVE_TIMEOUT_IN_MILLISECONDS
          });
          leaf.detach();

          return { error: '', scenarios: [{ isOriginalNameKept, isRenamed, name: 'canvas-paste' }], settingsFound: true };
        } catch (error) {
          return { error: String(error), scenarios: [], settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentRenameMode = prior.attachmentRenameMode;
            settings.attachmentFolderPath = prior.attachmentFolderPath;
            settings.generatedAttachmentFileName = prior.generatedAttachmentFileName;
            settings.screenshotFilePaths = prior.screenshotFilePaths;
            settings.shouldKeepNamesOfPastedNonScreenshotFiles = prior.shouldKeepNamesOfPastedNonScreenshotFiles;
          });
          await fsPromises.rm(sourceFolderPath, { force: true, recursive: true }).catch(() => {
            // Best-effort temp cleanup.
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.error).toBe('');
    expect(result.scenarios).toEqual([{ isOriginalNameKept: false, isRenamed: true, name: 'canvas-paste' }]);
  }, 120_000);
});
