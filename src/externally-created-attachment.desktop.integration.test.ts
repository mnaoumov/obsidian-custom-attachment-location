import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for the second half of issue #59: an attachment another plugin writes
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
  save?: () => Promise<void>;
}

interface EditorLike {
  replaceSelection: (text: string) => void;
}

interface ForeignAttachmentResult {
  readonly finalPaths: readonly string[];
  readonly linkTargetPath: null | string;
  readonly noteContent: string;
  readonly properPath: string;
  readonly settingsFound: boolean;
}

interface RunParams {
  /**
   * Whether the creating plugin links the file from the note. Issue #88's shape when `false`: a plugin
   * writing a file for its own use, which nothing links to and which must stay where it was written.
   */
  readonly isLinked?: boolean;
  /**
   * Issue #82's shape instead of issue #59's: a note inside a folder, the attachment folder template
   * `./assets/{{noteFileName}}`, the vault on RELATIVE Markdown links, and the embed spelled relative to
   * the note. That spelling holds the vault path nowhere, which is what used to write the folder twice.
   */
  readonly isRelativeLinkScenario: boolean;
  readonly shouldRename: boolean;
}

describe('Attachments created by other plugins (issue #59)', () => {
  async function run(params: RunParams): Promise<ForeignAttachmentResult> {
    return await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, isLinked, isRelativeLinkScenario, shouldRename: isRenameEnabled }): Promise<ForeignAttachmentResult> {
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

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isForeignSettings);
        if (!settingsComponent) {
          return { finalPaths: [], linkTargetPath: null, noteContent: '', properPath: '', settingsFound: false };
        }

        /*
         * These tests share one Obsidian instance with every other integration file, and the settings
         * are the live, saved ones. Snapshot them and put them back, or the next test in the run inherits
         * this folder template.
         */
        const originalSettings = {
          attachmentFolderPath: settingsComponent.settings.attachmentFolderPath,
          generatedAttachmentFileName: settingsComponent.settings.generatedAttachmentFileName,
          renameAttachmentsCreatedByOtherPluginsMode: settingsComponent.settings.renameAttachmentsCreatedByOtherPluginsMode
        };

        // The vault's link format is shared state too, and the relative scenario changes it.
        const originalNewLinkFormat = app.vault.getConfig('newLinkFormat');
        const originalUseMarkdownLinks = app.vault.getConfig('useMarkdownLinks');

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        await settingsComponent.editAndSave((settings) => {
          // The enum's values ARE the display strings; this code runs inside Obsidian and cannot import them.
          settings.renameAttachmentsCreatedByOtherPluginsMode = isRenameEnabled ? 'All' : 'None';
          settings.generatedAttachmentFileName = `renamed-${stamp}`;
        });

        try {
          let notePath: string;
          let foreignFolder: string;
          let insertedEmbed: string;
          let properPath: string;
          if (isRelativeLinkScenario) {
            app.vault.setConfig('newLinkFormat', 'relative');
            app.vault.setConfig('useMarkdownLinks', true);
            await settingsComponent.editAndSave((settings) => {
              settings.attachmentFolderPath = './assets/{{noteFileName}}';
            });
            const noteFolder = `notes-${stamp}`;
            const noteBaseName = `Test Note ${stamp}`;
            await app.vault.createFolder(noteFolder);
            notePath = `${noteFolder}/${noteBaseName}.md`;
            // Media Extended writes into the folder `getAvailablePathForAttachment` hands it, which is already the right one.
            foreignFolder = `${noteFolder}/assets/${noteBaseName}`;
            insertedEmbed = `![](./assets/${encodeURI(noteBaseName)}/mx-img-${stamp}.png)`;
            properPath = `${foreignFolder}/renamed-${stamp}.png`;
          } else {
            await settingsComponent.editAndSave((settings) => {
              settings.attachmentFolderPath = `./proper-${stamp}`;
            });
            notePath = `foreign-note-${stamp}.md`;
            // Exactly what Media Extended does: its own folder, its own file name, a direct binary write.
            foreignFolder = `foreign-${stamp}`;
            /*
             * The SHORTEST-FORM spelling, `![[<file name>|<alias>]]`, because that is what Obsidian's link
             * generation produces by default and therefore what Media Extended actually inserts. Asserting
             * only the full-path spelling here is what let a dangling embed ship past this suite once.
             */
            insertedEmbed = `![[mx-img-${stamp}.png|Some title]]`;
            properPath = `proper-${stamp}/renamed-${stamp}.png`;
          }

          const note = await app.vault.create(notePath, '');
          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          await sleep(500);

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
          if (isLinked) {
            view.editor?.replaceSelection(insertedEmbed);
          }

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
          // What Obsidian itself resolves the one embed in the note to — the only judge of a broken link.
          const linkMatch = /\]\((?<markdownPath>[^)]+)\)|\[\[(?<wikiPath>[^\]|]+)/.exec(noteContent);
          const linkPath = linkMatch?.groups?.['markdownPath'] ?? linkMatch?.groups?.['wikiPath'];
          const linkTargetPath = linkPath === undefined
            ? null
            : app.metadataCache.getFirstLinkpathDest(decodeURI(linkPath), note.path)?.path ?? null;

          leaf.detach();

          return { finalPaths, linkTargetPath, noteContent, properPath, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = originalSettings.attachmentFolderPath;
            settings.generatedAttachmentFileName = originalSettings.generatedAttachmentFileName;
            settings.renameAttachmentsCreatedByOtherPluginsMode = originalSettings.renameAttachmentsCreatedByOtherPluginsMode;
          });
          app.vault.setConfig('newLinkFormat', originalNewLinkFormat);
          app.vault.setConfig('useMarkdownLinks', originalUseMarkdownLinks);
        }
      },
      input: {
        findPluginSettingsComponent,
        isLinked: params.isLinked ?? true,
        isRelativeLinkScenario: params.isRelativeLinkScenario,
        shouldRename: params.shouldRename
      },
      vaultPath: getTemporaryVault().path
    });
  }

  it('moves and renames a foreign attachment when the setting is on, and repoints the embed', async () => {
    const result = await run({ isRelativeLinkScenario: false, shouldRename: true });

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^proper-[\d-]+\/renamed-[\d-]+\.png$/);
    // The embed the creating plugin inserted must follow the file, or the note is left broken.
    expect(result.noteContent).toContain('renamed-');
    expect(result.noteContent).not.toContain('mx-img-');
    expect(result.linkTargetPath).toBe(result.properPath);
  }, 120_000);

  it('leaves a foreign attachment exactly where it was written when the setting is off', async () => {
    const result = await run({ isRelativeLinkScenario: false, shouldRename: false });

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^foreign-[\d-]+\/mx-img-[\d-]+\.png$/);
    // Nothing moved, so the embed still points where the creating plugin put it.
    expect(result.noteContent).toContain('mx-img-');
  }, 120_000);

  it('leaves a file no note links to where its plugin wrote it, even with the setting on (issue #88)', async () => {
    const result = await run({ isLinked: false, isRelativeLinkScenario: false, shouldRename: true });

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^foreign-[\d-]+\/mx-img-[\d-]+\.png$/);
  }, 120_000);

  it('repoints an embed spelled relative to the note without writing its folder twice (issue #82)', async () => {
    const result = await run({ isRelativeLinkScenario: true, shouldRename: true });

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toEqual([result.properPath]);
    expect(result.noteContent).not.toContain('mx-img-');
    expect(result.noteContent).not.toMatch(/assets\/[^/)]+\/assets\//);
    // The embed has to resolve to the moved file in Obsidian's own eyes, whatever spelling it took.
    expect(result.linkTargetPath).toBe(result.properPath);
  }, 120_000);
});
