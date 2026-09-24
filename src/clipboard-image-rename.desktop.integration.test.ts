import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for issue #31 (an already-merged feature of this plugin): in
 * "Attachment rename mode: Only pasted images", an image inserted through the clipboard `insertFiles`
 * sink must be renamed per the configured `generatedAttachmentFileName` pattern EVEN when its source
 * name is not `Pasted image <timestamp>` (e.g. a Windows 11 Win+Shift+S screenshot backed by a temp
 * file). The fix flags the image by exact ArrayBuffer identity in the `insertFiles` interception, so
 * this drives the real `ClipboardManager.insertFiles` path (not the filename heuristic) and asserts
 * the saved attachment is renamed.
 */

interface AdapterWithFsPromises {
  fsPromises: FsPromisesLike;
}

interface ClipboardRenameResult {
  readonly originalNameSurvived: boolean;
  readonly renamedPaths: readonly string[];
  readonly settingsFound: boolean;
}

interface FsPromisesLike {
  unlink: (path: string) => Promise<void>;
  writeFile: (path: string, data: Uint8Array) => Promise<void>;
}

interface InsertFilesClipboardManager {
  insertFiles: (importedAttachments: unknown[]) => Promise<void>;
}

interface MarkdownEditModeLike {
  clipboardManager?: InsertFilesClipboardManager;
}

interface MarkdownViewLike {
  editMode?: MarkdownEditModeLike;
}

interface OsModuleLike {
  tmpdir: () => string;
}

interface PathModuleLike {
  join: (...parts: string[]) => string;
}

/*
 * Desktop-only: no Android emulator is available in this environment. The clipboard `insertFiles` rename path is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to
 * Android once an emulator exists.
 */

describe('Clipboard-inserted image is renamed in "Only pasted images" mode (issue #31)', () => {
  it('renames a non-"Pasted image"-named clipboard image via the generated pattern', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent }): Promise<ClipboardRenameResult> {
        interface RenameSettings {
          attachmentFolderPath: string;
          attachmentRenameMode: string;
          generatedAttachmentFileName: string;
          isPathIgnored: (path: string) => boolean;
        }

        function isRenameSettings(value: unknown): value is RenameSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentRenameMode'] === 'string'
            && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isRenameSettings);
        if (!settingsComponent) {
          return { originalNameSurvived: true, renamedPaths: [], settingsFound: false };
        }

        const priorAttachmentRenameMode = settingsComponent.settings.attachmentRenameMode;
        const priorAttachmentFolderPath = settingsComponent.settings.attachmentFolderPath;
        const priorGeneratedAttachmentFileName = settingsComponent.settings.generatedAttachmentFileName;
        await settingsComponent.editAndSave((settings) => {
          settings.attachmentRenameMode = 'Only pasted images';
          settings.attachmentFolderPath = './';
          settings.generatedAttachmentFileName = 'pasted-{{date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}}';
        });

        try {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const note = await app.vault.create(`clip-note-${stamp}.md`, '');
          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          await sleep(500);

          // The clipboard manager whose `insertFiles` this plugin patches lives on the active markdown view.
          const viewUnknown: unknown = leaf.view;
          const view = viewUnknown as MarkdownViewLike;
          const clipboardManager = view.editMode?.clipboardManager;
          if (!clipboardManager) {
            return { originalNameSurvived: true, renamedPaths: [], settingsFound: true };
          }

          // A genuine clipboard image whose source name is NOT `Pasted image <timestamp>` (the exact
          // Win+Shift+S regression): a real temp file OUTSIDE the vault backs it (so the plugin's
          // `trySetByPath` stat succeeds), and only the ArrayBuffer-identity flag can mark it pasted.
          const originalBaseName = `screenshot-original-${stamp}`;
          // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
          const os = require('node:os') as OsModuleLike;
          // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
          const nodePath = require('node:path') as PathModuleLike;
          const temporaryFilePath = nodePath.join(os.tmpdir(), `${originalBaseName}.png`);
          const adapterUnknown: unknown = app.vault.adapter;
          const fsPromises = (adapterUnknown as AdapterWithFsPromises).fsPromises;
          await fsPromises.writeFile(temporaryFilePath, new Uint8Array(8));

          const importedAttachment = {
            data: Promise.resolve(new ArrayBuffer(8)),
            extension: 'png',
            filepath: temporaryFilePath,
            name: `${originalBaseName}.png`
          };
          await clipboardManager.insertFiles([importedAttachment]);

          // The save runs through the plugin's saveAttachment patch; poll until a PNG appears in the vault.
          let renamedPaths: string[] = [];
          const deadline = Date.now() + 15_000;
          while (Date.now() < deadline) {
            renamedPaths = app.vault.getFiles()
              .map((file) => file.path)
              .filter((path) => /pasted-\d+\.png$/.test(path));
            if (renamedPaths.length > 0) {
              break;
            }
            await sleep(300);
          }

          const isOriginalNameSurvived = app.vault.getFiles().some((file) => file.path.includes(originalBaseName));
          await fsPromises.unlink(temporaryFilePath).catch(() => {
            // Best-effort temp cleanup.
          });

          // Detach the opened leaf so it does not keep the workspace focused on this note's editor.
          leaf.detach();

          return { originalNameSurvived: isOriginalNameSurvived, renamedPaths, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentRenameMode = priorAttachmentRenameMode;
            settings.attachmentFolderPath = priorAttachmentFolderPath;
            settings.generatedAttachmentFileName = priorGeneratedAttachmentFileName;
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // Issue #31: the clipboard image was renamed via the generated pattern...
    expect(result.renamedPaths).toHaveLength(1);
    expect(result.renamedPaths[0]).toMatch(/pasted-\d+\.png$/);
    // ...and its original (non-"Pasted image") name was NOT kept.
    expect(result.originalNameSurvived).toBe(false);
  }, 120_000);
});
