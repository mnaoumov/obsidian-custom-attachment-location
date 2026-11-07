import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for the per-operation templates of a new attachment: a pasted screenshot and a dropped file
 * each go to their own folder under their own name, through Obsidian's real paste and drop handlers.
 *
 * The paste and the drop are DISPATCHED for the reason `screenshot-file-paste.desktop.integration.test.ts` gives: a
 * trusted one would need the user's system clipboard or an OS drag. The file carries its disk path through the
 * `path` property this plugin's `webUtils.getPathForFile` patch reads.
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
  readonly writeFile: (path: string, data: Uint8Array) => Promise<void>;
}

interface MarkdownViewLike {
  readonly editor?: EditorLike;
}

interface MkdirOptions {
  readonly recursive: boolean;
}

interface OperationTemplatesResult {
  readonly error: string;
  readonly savedPaths: readonly string[];
  readonly settingsFound: boolean;
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

describe('Per-operation templates for new attachments', () => {
  it('saves a pasted screenshot and a dropped file each by its own operation\'s folder and name', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, lib: { waitUntil } }): Promise<OperationTemplatesResult> {
        interface OperationSettings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          droppedFileAttachmentFileName: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          droppedFileAttachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          pastedImageAttachmentFileName: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          pastedImageAttachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldKeepNamesOfPastedNonScreenshotFiles: boolean;
        }

        function isOperationSettings(value: unknown): value is OperationSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentRenameMode'] === 'string'
            && typeof (value as Record<string, unknown>)['pastedImageAttachmentFolderPath'] === 'string';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isOperationSettings);
        if (!settingsComponent) {
          return { error: '', savedPaths: [], settingsFound: false };
        }

        // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
        const os = require('node:os') as OsModuleLike;
        // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
        const nodePath = require('node:path') as PathModuleLike;
        const adapterUnknown: unknown = app.vault.adapter;
        const fsPromises = (adapterUnknown as AdapterWithFsPromises).fsPromises;
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const sourceFolderPath = nodePath.join(os.tmpdir(), `custom-attachment-location-operation-source-${stamp}`);
        await fsPromises.mkdir(sourceFolderPath, { recursive: true });

        const prior = { ...settingsComponent.settings };
        const noteFolderPath = `operation-templates-${stamp}`;
        const savedPaths: string[] = [];

        try {
          await settingsComponent.editAndSave((settings) => {
            // `All`, so the drop is renamed too and its template decides the name.
            settings.attachmentRenameMode = 'All';
            settings.attachmentFolderPath = './default';
            settings.shouldKeepNamesOfPastedNonScreenshotFiles = false;
            settings.pastedImageAttachmentFolderPath = './screenshots';
            settings.pastedImageAttachmentFileName = 'shot';
            settings.droppedFileAttachmentFolderPath = './drops';
            settings.droppedFileAttachmentFileName = 'dropped {{originalAttachmentFileName}}';
          });
          await app.vault.createFolder(noteFolderPath);

          for (const gesture of ['paste', 'drop'] as const) {
            const originalBaseName = `original-${gesture}`;
            const sourceFilePath = nodePath.join(sourceFolderPath, `${originalBaseName}.png`);
            const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
            await fsPromises.writeFile(sourceFilePath, bytes);

            const note = await app.vault.create(`${noteFolderPath}/note-${gesture}.md`, '');
            const leaf = app.workspace.getLeaf(true);
            await leaf.openFile(note);
            await app.workspace.revealLeaf(leaf);
            app.workspace.setActiveLeaf(leaf, { focus: true });
            await sleep(500);

            const viewUnknown: unknown = leaf.view;
            const contentDom = (viewUnknown as MarkdownViewLike).editor?.cm?.contentDOM;
            if (!contentDom) {
              return { error: 'no editor content DOM', savedPaths, settingsFound: true };
            }
            contentDom.focus();

            const file = new File([bytes], `${originalBaseName}.png`, { type: 'image/png' });
            Object.defineProperty(file, 'path', { value: sourceFilePath });
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(file);

            if (gesture === 'paste') {
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

            const SAVE_TIMEOUT_IN_MILLISECONDS = 10_000;
            const pngCountBefore = savedPaths.length;
            await waitUntil({
              message: `the ${gesture}d attachment to be saved`,
              predicate: () => {
                const pngPaths = app.vault.getFiles().map((vaultFile) => vaultFile.path).filter((path) => path.startsWith(`${noteFolderPath}/`) && path.endsWith('.png'));
                if (pngPaths.length > pngCountBefore) {
                  savedPaths.splice(0, savedPaths.length, ...pngPaths.sort());
                  return true;
                }
                return false;
              },
              timeoutInMilliseconds: SAVE_TIMEOUT_IN_MILLISECONDS
            });
            leaf.detach();
          }

          return { error: '', savedPaths, settingsFound: true };
        } catch (error) {
          return { error: String(error), savedPaths, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentRenameMode = prior.attachmentRenameMode;
            settings.attachmentFolderPath = prior.attachmentFolderPath;
            settings.shouldKeepNamesOfPastedNonScreenshotFiles = prior.shouldKeepNamesOfPastedNonScreenshotFiles;
            settings.pastedImageAttachmentFolderPath = prior.pastedImageAttachmentFolderPath;
            settings.pastedImageAttachmentFileName = prior.pastedImageAttachmentFileName;
            settings.droppedFileAttachmentFolderPath = prior.droppedFileAttachmentFolderPath;
            settings.droppedFileAttachmentFileName = prior.droppedFileAttachmentFileName;
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
    const noteFolderPath = result.savedPaths[0]?.split('/', 1)[0] ?? '';
    expect(result.savedPaths).toEqual([
      `${noteFolderPath}/drops/dropped original-drop.png`,
      `${noteFolderPath}/screenshots/shot.png`
    ]);
  }, 120_000);
});
