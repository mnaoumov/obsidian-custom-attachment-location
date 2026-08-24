import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for the second half of issue #59 (G97): an attachment another plugin writes
 * straight into the vault must be moved and renamed per the configured templates, once the opt-in
 * setting is on — and left exactly where it was written when the setting is off.
 *
 * The foreign write is reproduced the way Media Extended actually does it: compose a path of your own
 * and call `vault.createBinary`, never `app.saveAttachment`. That is precisely why the plugin's normal
 * naming pipeline (and `Attachment rename mode: All` with it) cannot see the file at all.
 *
 * Desktop-only: no Android emulator is available in this environment. The behavior is cross-platform,
 * so renaming this file to `*.cross-platform.integration.test.ts` lifts it to Android once one exists.
 */

interface ForeignAttachmentResult {
  readonly finalPaths: readonly string[];
  readonly settingsFound: boolean;
}

describe('Attachments created by other plugins (issue #59)', () => {
  async function run(shouldRename: boolean): Promise<ForeignAttachmentResult> {
    return await evalInObsidian({
      async callback({ app, shouldRename: isRenameEnabled }): Promise<ForeignAttachmentResult> {
        interface ForeignSettings {
          attachmentFolderPath: string;
          attachmentRenameMode: string;
          generatedAttachmentFileName: string;
          shouldRenameAttachmentsCreatedByOtherPlugins: boolean;
        }

        function isForeignSettings(value: unknown): value is ForeignSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldRenameAttachmentsCreatedByOtherPlugins'] === 'boolean'
            && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        function findSettings(): ForeignSettings | null {
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
            if (isForeignSettings(record['settings'])) {
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

        const settings = findSettings();
        if (!settings) {
          return { finalPaths: [], settingsFound: false };
        }

        /*
         * These tests share one Obsidian instance with every other integration file, and the settings
         * object is the live one. Snapshot it and put it back, or the next test in the run inherits
         * this folder template.
         */
        const originalSettings = {
          attachmentFolderPath: settings.attachmentFolderPath,
          generatedAttachmentFileName: settings.generatedAttachmentFileName,
          shouldRenameAttachmentsCreatedByOtherPlugins: settings.shouldRenameAttachmentsCreatedByOtherPlugins
        };
        function restoreSettings(currentSettings: ForeignSettings): void {
          currentSettings.attachmentFolderPath = originalSettings.attachmentFolderPath;
          currentSettings.generatedAttachmentFileName = originalSettings.generatedAttachmentFileName;
          currentSettings.shouldRenameAttachmentsCreatedByOtherPlugins = originalSettings.shouldRenameAttachmentsCreatedByOtherPlugins;
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        settings.shouldRenameAttachmentsCreatedByOtherPlugins = isRenameEnabled;
        settings.attachmentFolderPath = `./proper-${stamp}`;
        settings.generatedAttachmentFileName = `renamed-${stamp}`;

        const note = await app.vault.create(`foreign-note-${stamp}.md`, '');
        const leaf = app.workspace.getLeaf(false);
        await leaf.openFile(note);
        await app.workspace.revealLeaf(leaf);
        await sleep(500);

        // Exactly what Media Extended does: its own folder, its own file name, a direct binary write.
        const foreignFolder = `foreign-${stamp}`;
        await app.vault.createFolder(foreignFolder);
        const foreignPath = `${foreignFolder}/mx-img-${stamp}.png`;
        await app.vault.createBinary(foreignPath, new ArrayBuffer(8));

        const properPath = `proper-${stamp}/renamed-${stamp}.png`;
        const deadline = Date.now() + 15_000;
        while (Date.now() < deadline) {
          if (app.vault.getFileByPath(properPath)) {
            break;
          }
          await sleep(300);
        }

        // A settled read: when the setting is off, nothing should ever have moved.
        await sleep(1000);
        const finalPaths = app.vault.getFiles()
          .map((file) => file.path)
          .filter((path) => path.includes(stamp) && path.endsWith('.png'));

        leaf.detach();
        restoreSettings(settings);

        return { finalPaths, settingsFound: true };
      },
      input: { shouldRename },
      vaultPath: getTemporaryVault().path
    });
  }

  it('moves and renames a foreign attachment when the setting is on', async () => {
    const result = await run(true);

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^proper-[\d-]+\/renamed-[\d-]+\.png$/);
  }, 120_000);

  it('leaves a foreign attachment exactly where it was written when the setting is off', async () => {
    const result = await run(false);

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^foreign-[\d-]+\/mx-img-[\d-]+\.png$/);
  }, 120_000);
});
