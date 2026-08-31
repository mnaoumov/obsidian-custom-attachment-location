import type { TAbstractFile } from 'obsidian';

import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for the two navigation commands ([[T692-P4]]). Both are resolved through the
 * plugin's own machinery — the folder from the attachment-folder pattern, the owning note from the
 * link graph — so only a real vault with a real metadata cache proves they agree with each other.
 */

interface FileExplorerLike {
  revealInFolder(abstractFile: TAbstractFile): void;
}

interface NavigationResult {
  readonly activeFilePathAfterGoToOwningNote: string;
  readonly attachmentPath: string;
  readonly expectedAttachmentFolderPath: string;
  readonly isFileExplorerFound: boolean;
  readonly notePath: string;
  readonly revealedPath: string;
  readonly settingsFound: boolean;
}

describe('Navigation between a note and its attachments', () => {
  it('reveals the note\'s attachment folder and comes back from the attachment', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<NavigationResult> {
        interface Settings {
          attachmentFolderPath: string;
          emptyFolderBehavior: unknown;
          isPathIgnored(path: string): boolean;
        }
        function isSettings(value: unknown): value is Settings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string'
            && 'emptyFolderBehavior' in (value as Record<string, unknown>);
        }
        /*
         * The plugin does not expose its settings publicly, so locate the live settings object by
         * walking the plugin's component tree.
         */
        function findSettings(): null | Settings {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [app.plugins.getPlugin('obsidian-custom-attachment-location')];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            if (isSettings(record['settings'])) {
              return record['settings'];
            }
            let values: unknown[] = [];
            if (Array.isArray(current)) {
              values = current;
            } else if (current instanceof Map) {
              values = [...current.values()];
            } else {
              for (const [key, value] of Object.entries(record)) {
                if (!block.has(key)) {
                  values.push(value);
                }
              }
            }
            for (const value of values) {
              if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
                queue.push(value);
              }
            }
          }
          return null;
        }

        async function waitUntil(checkIsSettled: () => boolean): Promise<void> {
          for (let attempt = 0; attempt < 40 && !checkIsSettled(); attempt++) {
            await sleep(250);
          }
        }

        const emptyResult: NavigationResult = {
          activeFilePathAfterGoToOwningNote: '',
          attachmentPath: '',
          expectedAttachmentFolderPath: '',
          isFileExplorerFound: false,
          notePath: '',
          revealedPath: '',
          settingsFound: false
        };

        const settings = findSettings();
        if (!settings) {
          return emptyResult;
        }

        // eslint-disable-next-line no-template-curly-in-string -- Intentional plugin token, not a JS template literal.
        settings.attachmentFolderPath = './_/${noteFileName}';

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const noteBaseName = `NavNote-${stamp}`;
        const notePath = `${noteBaseName}.md`;
        const attachmentFolderPath = `_/${noteBaseName}`;
        const attachmentPath = `${attachmentFolderPath}/img-${stamp}.png`;

        await app.vault.createFolder(attachmentFolderPath);
        await app.vault.createBinary(attachmentPath, new ArrayBuffer(8));
        const note = await app.vault.create(notePath, `![[${attachmentPath}]]\n`);

        const attachmentFile = app.vault.getFileByPath(attachmentPath);
        if (!attachmentFile) {
          return { ...emptyResult, settingsFound: true };
        }

        const fileExplorer = app.internalPlugins.getEnabledPluginById('file-explorer') as FileExplorerLike | null;
        if (!fileExplorer) {
          return { ...emptyResult, settingsFound: true };
        }

        // Go to attachment folder: from the note, reveal the folder the pattern resolves to.
        await app.workspace.getLeaf(false).openFile(note);
        await sleep(500);

        let revealedPath = '';
        const originalRevealInFolder = fileExplorer.revealInFolder.bind(fileExplorer);
        fileExplorer.revealInFolder = (abstractFile: TAbstractFile): void => {
          revealedPath = abstractFile.path;
        };
        try {
          app.commands.executeCommandById('obsidian-custom-attachment-location:go-to-attachment-folder');
          await waitUntil(() => revealedPath !== '');
        } finally {
          fileExplorer.revealInFolder = originalRevealInFolder;
        }

        // Go to owning note: from the attachment, open the note that references it.
        await app.workspace.getLeaf(false).openFile(attachmentFile);
        await waitUntil(() => app.workspace.getActiveFile()?.path === attachmentPath);

        app.commands.executeCommandById('obsidian-custom-attachment-location:go-to-owning-note');
        await waitUntil(() => app.workspace.getActiveFile()?.path === notePath);

        return {
          activeFilePathAfterGoToOwningNote: app.workspace.getActiveFile()?.path ?? '',
          attachmentPath,
          expectedAttachmentFolderPath: attachmentFolderPath,
          isFileExplorerFound: true,
          notePath,
          revealedPath,
          settingsFound: true
        };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.isFileExplorerFound).toBe(true);
    expect(result.revealedPath).toBe(result.expectedAttachmentFolderPath);
    expect(result.activeFilePathAfterGoToOwningNote).toBe(result.notePath);
  }, 180_000);
});
