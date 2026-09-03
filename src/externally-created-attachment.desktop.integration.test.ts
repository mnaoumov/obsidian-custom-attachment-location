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

interface EditableViewLike {
  readonly editor?: EditorLike;
  save?(): Promise<void>;
}

interface EditorLike {
  replaceSelection(text: string): void;
}

interface ForeignAttachmentResult {
  readonly finalPaths: readonly string[];
  readonly noteContent: string;
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
          renameAttachmentsCreatedByOtherPluginsMode: string;
        }

        function isForeignSettings(value: unknown): value is ForeignSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['renameAttachmentsCreatedByOtherPluginsMode'] === 'string'
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
          return { finalPaths: [], noteContent: '', settingsFound: false };
        }

        /*
         * These tests share one Obsidian instance with every other integration file, and the settings
         * object is the live one. Snapshot it and put it back, or the next test in the run inherits
         * this folder template.
         */
        const originalSettings = {
          attachmentFolderPath: settings.attachmentFolderPath,
          generatedAttachmentFileName: settings.generatedAttachmentFileName,
          renameAttachmentsCreatedByOtherPluginsMode: settings.renameAttachmentsCreatedByOtherPluginsMode
        };
        function restoreSettings(currentSettings: ForeignSettings): void {
          currentSettings.attachmentFolderPath = originalSettings.attachmentFolderPath;
          currentSettings.generatedAttachmentFileName = originalSettings.generatedAttachmentFileName;
          currentSettings.renameAttachmentsCreatedByOtherPluginsMode = originalSettings.renameAttachmentsCreatedByOtherPluginsMode;
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        // The enum's values ARE the display strings; this code runs inside Obsidian and cannot import them.
        settings.renameAttachmentsCreatedByOtherPluginsMode = isRenameEnabled ? 'All' : 'None';
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

        /*
         * ...and then, as soon as that write resolves, it inserts its own embed into the editor — by
         * which time the `create` handler has ALREADY begun moving the file. That ordering is the
         * whole risk in catching an attachment after the fact, and it is why *Paste image rename*
         * rewrites the current editor line by hand instead of trusting the rename to do it. Assert
         * the embed ends up pointing at the moved file.
         */
        const view = leaf.view as EditableViewLike;
        /*
         * The SHORTEST-FORM spelling, `![[<file name>|<alias>]]`, because that is what Obsidian's link
         * generation produces by default and therefore what Media Extended actually inserts. Asserting
         * only the full-path spelling here is what let a dangling embed ship past this suite once.
         */
        view.editor?.replaceSelection(`![[mx-img-${stamp}.png|Some title]]`);

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

        await view.save?.();
        const noteContent = await app.vault.read(note);

        leaf.detach();
        restoreSettings(settings);

        return { finalPaths, noteContent, settingsFound: true };
      },
      input: { shouldRename },
      vaultPath: getTemporaryVault().path
    });
  }

  it('moves and renames a foreign attachment when the setting is on, and repoints the embed', async () => {
    const result = await run(true);

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^proper-[\d-]+\/renamed-[\d-]+\.png$/);
    // The embed the creating plugin inserted must follow the file, or the note is left broken.
    expect(result.noteContent).toContain('renamed-');
    expect(result.noteContent).not.toContain('mx-img-');
  }, 120_000);

  it('leaves a foreign attachment exactly where it was written when the setting is off', async () => {
    const result = await run(false);

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^foreign-[\d-]+\/mx-img-[\d-]+\.png$/);
    // Nothing moved, so the embed still points where the creating plugin put it.
    expect(result.noteContent).toContain('mx-img-');
  }, 120_000);
});
