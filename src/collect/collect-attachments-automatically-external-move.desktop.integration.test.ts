import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * `Collect attachments automatically` when a note is moved OUTSIDE Obsidian, from the OS file manager.
 *
 * Reported against `Consistent Attachments and Links` before collecting moved here: moving `note.md` into a new
 * folder from Finder made the automatic collect read the note at its OLD path and leave the attachment behind.
 * The move here is a real filesystem rename through Node's `fs`, so Obsidian learns of it from its own file
 * watcher, exactly as it does for Finder or Explorer.
 *
 * The watcher reports the new path before it drops the old one. The collect for the moved note starts in that
 * gap, and its backlink check still finds the old path in the vault, reads it, and gets `ENOENT`.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
// Under the transport's ~30s per-closure cap, spent at most twice plus the settle. The watcher reports a move within a second.
const WAIT_TIMEOUT_IN_MILLISECONDS = 8000;
// Long enough for a collect stuck on the stale path to have given up.
const SETTLE_IN_MILLISECONDS = 3000;

interface ExternalMoveResult {
  readonly filePaths: readonly string[];
  readonly isNodeFsAvailable: boolean;
  readonly settingsFound: boolean;
}

async function runExternalMove(): Promise<ExternalMoveResult> {
  return await evalInObsidian({
    async callback({
      app,
      findPluginSettingsComponent: findSettingsComponent,
      lib: { waitUntil },
      pluginId,
      settleInMilliseconds,
      waitTimeoutInMilliseconds
    }): Promise<ExternalMoveResult> {
      interface ExternalMoveSettings {
        attachmentFolderPath: string;
        collectedAttachmentFolderPath: string;
        shouldCollectAttachmentsAutomatically: boolean;
        shouldRenameCollectedAttachments: boolean;
      }

      interface FullPathAdapter {
        readonly getFullPath: (normalizedPath: string) => string;
      }

      interface NodeFs {
        readonly mkdirSync: (path: string) => void;
        readonly renameSync: (oldPath: string, newPath: string) => void;
      }

      interface NodeRequireHost {
        readonly require: (id: string) => unknown;
      }

      function isExternalMoveSettings(value: unknown): value is ExternalMoveSettings {
        const record = value as null | Record<string, unknown>;
        return typeof value === 'object' && record !== null
          && typeof record['attachmentFolderPath'] === 'string'
          && typeof record['collectedAttachmentFolderPath'] === 'string'
          && typeof record['shouldCollectAttachmentsAutomatically'] === 'boolean'
          && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
      }

      function isFullPathAdapter(value: unknown): value is FullPathAdapter {
        return typeof (value as Partial<FullPathAdapter>).getFullPath === 'function';
      }

      function isNodeRequireHost(value: unknown): value is NodeRequireHost {
        return typeof (value as Partial<NodeRequireHost>).require === 'function';
      }

      function isNodeFs(value: unknown): value is NodeFs {
        const record = value as Partial<NodeFs>;
        return typeof record.mkdirSync === 'function' && typeof record.renameSync === 'function';
      }

      const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isExternalMoveSettings);
      if (!settingsComponent) {
        return { filePaths: [], isNodeFsAvailable: false, settingsFound: false };
      }

      // Desktop Obsidian runs its renderer with Node integration, so `require` is the renderer's own.
      const requireHost: unknown = window;
      const fs = isNodeRequireHost(requireHost) ? requireHost.require('node:fs') : null;
      const adapter = app.vault.adapter;
      if (!isNodeFs(fs) || !isFullPathAdapter(adapter)) {
        return { filePaths: [], isNodeFsAvailable: false, settingsFound: true };
      }

      const prior = { ...settingsComponent.settings };
      const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
      const rootFolderPath = `_ExternalMove-${stamp}`;
      const oldNotePath = `${rootFolderPath}/note.md`;
      const newFolderPath = `${rootFolderPath}/New`;
      const newNotePath = `${newFolderPath}/note.md`;
      const oldAttachmentPath = `${rootFolderPath}/assets/image.png`;
      const newAttachmentPath = `${newFolderPath}/assets/image.png`;

      function listFiles(): string[] {
        return app.vault.getFiles().map((file) => file.path).filter((path) => path.startsWith(`${rootFolderPath}/`)).sort();
      }

      try {
        await settingsComponent.editAndSave((settings) => {
          settings.attachmentFolderPath = './assets';
          settings.collectedAttachmentFolderPath = '';
          settings.shouldCollectAttachmentsAutomatically = false;
          settings.shouldRenameCollectedAttachments = false;
        });

        await app.vault.createFolder(`${rootFolderPath}/assets`);
        const attachment = await app.vault.createBinary(oldAttachmentPath, new ArrayBuffer(5));
        await app.vault.create(oldNotePath, `![[${oldAttachmentPath}]]\n`);
        await waitUntil({
          message: 'the staged embed was not indexed',
          predicate: () => app.metadataCache.getBacklinksForFile(attachment).keys().length > 0,
          timeoutInMilliseconds: waitTimeoutInMilliseconds
        });

        // Turned on only now, so creating the note did not already collect it.
        await settingsComponent.editAndSave((settings) => {
          settings.shouldCollectAttachmentsAutomatically = true;
        });

        fs.mkdirSync(adapter.getFullPath(newFolderPath));
        fs.renameSync(adapter.getFullPath(oldNotePath), adapter.getFullPath(newNotePath));

        await waitUntil({
          message: 'Obsidian did not pick up the external move',
          predicate: () => app.vault.getFileByPath(newNotePath) !== null && app.vault.getFileByPath(oldNotePath) === null,
          timeoutInMilliseconds: waitTimeoutInMilliseconds
        });

        try {
          await waitUntil({
            message: 'the attachment was not collected after the external move',
            predicate: () => app.vault.getFileByPath(newAttachmentPath) !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
        } catch {
          // The assertion outside reports what was left where, which says more than the timeout.
        }

        await sleep(settleInMilliseconds);
        return { filePaths: listFiles(), isNodeFsAvailable: true, settingsFound: true };
      } finally {
        await settingsComponent.editAndSave((settings) => {
          settings.shouldCollectAttachmentsAutomatically = false;
        });
        const rootFolder = app.vault.getAbstractFileByPath(rootFolderPath);
        if (rootFolder) {
          await app.fileManager.trashFile(rootFolder);
        }
        await settingsComponent.editAndSave((settings) => {
          settings.attachmentFolderPath = prior.attachmentFolderPath;
          settings.collectedAttachmentFolderPath = prior.collectedAttachmentFolderPath;
          settings.shouldCollectAttachmentsAutomatically = prior.shouldCollectAttachmentsAutomatically;
          settings.shouldRenameCollectedAttachments = prior.shouldRenameCollectedAttachments;
        });
      }
    },
    input: {
      findPluginSettingsComponent,
      pluginId: PLUGIN_ID,
      settleInMilliseconds: SETTLE_IN_MILLISECONDS,
      waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
    },
    vaultPath: getTemporaryVault().path
  });
}

describe('Collect attachments automatically after an external move', () => {
  it('collects the attachment into the moved note\'s folder', async () => {
    const result = await runExternalMove();

    expect(result.settingsFound).toBe(true);
    expect(result.isNodeFsAvailable).toBe(true);
    expect(result.filePaths.map((path) => path.split('/').slice(1).join('/'))).toEqual(['New/assets/image.png', 'New/note.md']);
  }, 90_000);
});
