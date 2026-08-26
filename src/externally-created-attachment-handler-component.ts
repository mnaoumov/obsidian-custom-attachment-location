import type {
  EditorChange,
  MarkdownView,
  TAbstractFile,
  WorkspaceLeaf
} from 'obsidian';

import { ViewType } from '@obsidian-typings/obsidian-public-latest/implementations';
import {
  App,
  Component,
  TFile
} from 'obsidian';
import { convertAsyncToSync } from 'obsidian-dev-utils/async';
import { printError } from 'obsidian-dev-utils/error';
import { createFolderSafe } from 'obsidian-dev-utils/obsidian/vault';
import {
  basename,
  dirname,
  join,
  makeFileName
} from 'obsidian-dev-utils/path';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { TokenValidator } from './token-validator.ts';

import { selfWriteRegistry } from './self-write-registry.ts';
import { Substitutions } from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';

const FRESHLY_CREATED_THRESHOLD_IN_MILLISECONDS = 10_000;

interface ExternallyCreatedAttachmentHandlerComponentConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly tokenValidator: TokenValidator;
}

/**
 * Applies the plugin's folder and file-name templates to attachments OTHER plugins create.
 *
 * The plugin's own naming pipeline hangs off `app.saveAttachment`. A plugin that composes a path itself
 * and writes it with `vault.createBinary` never reaches that pipeline — Media Extended's screenshots are
 * the reported case (issue #59): it asks `fileManager.getAvailablePathForAttachment` for a throwaway path
 * only to strip the file name back off and keep the folder, then invents its own name. Not even
 * `Attachment rename mode: All` helps, because that switch lives inside `saveAttachment` too.
 *
 * So the only place left to catch such a file is after it exists. This mirrors what the *Paste image
 * rename* plugin does, and it is deliberately GENERAL — it keys off nothing specific to any one plugin.
 *
 * Off by default: it reacts to writes the plugin did not make, so it must never change behavior on
 * upgrade.
 */
export class ExternallyCreatedAttachmentHandlerComponent extends Component {
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: ExternallyCreatedAttachmentHandlerComponentConstructorParams) {
    super();
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.tokenValidator = params.tokenValidator;
  }

  public override onload(): void {
    super.onload();
    /*
     * Registered by the caller only once the layout is ready. Registering earlier would hand this
     * handler a `create` event for every file of the initial vault scan.
     */
    this.registerEvent(this.app.vault.on('create', convertAsyncToSync(this.handleCreate.bind(this))));
  }

  /**
   * Resolves the note the templates are evaluated against.
   *
   * Usually that is simply the active file. But a foreign plugin need not be driven from a note at all:
   * Media Extended's screenshot command is issued from its OWN player leaf, so the active file is the
   * VIDEO, and taking the active file at face value would abandon every screenshot taken the way the
   * reporter of issue #59 takes them — confirmed against the real plugin, not reasoned about.
   *
   * The attachment still belongs to a note (Media Extended inserts its embed into the media note), so
   * fall back to the most recently active markdown leaf, which is that note.
   */
  private findNoteFile(): null | TFile {
    const activeFile = this.app.workspace.getActiveFile();
    if (activeFile && this.pluginSettingsComponent.isNoteEx(activeFile)) {
      return activeFile;
    }

    let mostRecentLeaf: null | WorkspaceLeaf = null;
    for (const leaf of this.app.workspace.getLeavesOfType(ViewType.Markdown)) {
      if (!mostRecentLeaf || leaf.activeTime > mostRecentLeaf.activeTime) {
        mostRecentLeaf = leaf;
      }
    }

    const noteFile = (mostRecentLeaf?.view as MarkdownView | undefined)?.file ?? null;
    if (!noteFile || !this.pluginSettingsComponent.isNoteEx(noteFile)) {
      return null;
    }

    return noteFile;
  }

  private async handleCreate(abstractFile: TAbstractFile): Promise<void> {
    if (!this.pluginSettingsComponent.settings.shouldRenameAttachmentsCreatedByOtherPlugins) {
      return;
    }

    if (!(abstractFile instanceof TFile)) {
      return;
    }

    const attachmentFile = abstractFile;

    /*
     * The plugin's own writes claim their path before writing it. Consuming the claim here is what
     * stops a `${prompt}` template prompting a second time for every attachment the plugin saves.
     */
    if (selfWriteRegistry.consume(attachmentFile.path)) {
      return;
    }

    if (this.pluginSettingsComponent.isNoteEx(attachmentFile)) {
      return;
    }

    /*
     * Only files created just now. A vault opening, a sync catching up or a folder import all replay
     * `create` for files that already existed, and none of those are an attachment the user is adding
     * to the note in front of them.
     *
     * A fixed window rather than the `timeoutInSeconds` setting: that one means "wait indefinitely"
     * at 0, which here would silently disable the guard and let a whole synced folder be renamed.
     * The value matches the pasted-image freshness threshold in `AttachmentSaver`.
     */
    if (Date.now() - attachmentFile.stat.ctime > FRESHLY_CREATED_THRESHOLD_IN_MILLISECONDS) {
      return;
    }

    if (this.pluginSettingsComponent.settings.isPathIgnored(attachmentFile.path)) {
      return;
    }

    const noteFile = this.findNoteFile();
    // The templates are relative to a note. Without one there is nothing to resolve them against.
    if (!noteFile) {
      return;
    }

    if (this.pluginSettingsComponent.settings.isPathIgnored(noteFile.path)) {
      return;
    }

    try {
      await this.moveToProperPath(attachmentFile, noteFile);
    } catch (error) {
      printError(error);
    }
  }

  private async moveToProperPath(attachmentFile: TFile, noteFile: TFile): Promise<void> {
    const readAttachmentFileContent = (): Promise<ArrayBuffer> => this.app.vault.readBinary(attachmentFile);

    const generatedAttachmentFileBaseName = await this.attachmentPathManager.getGeneratedAttachmentFileBaseName(
      new Substitutions({
        actionContext: ActionContext.ExternalAttachmentCreated,
        app: this.app,
        attachmentFileStats: attachmentFile.stat,
        noteFilePath: noteFile.path,
        originalAttachmentFileName: attachmentFile.name,
        pluginSettingsComponent: this.pluginSettingsComponent,
        readAttachmentFileContent,
        tokenValidator: this.tokenValidator
      })
    );

    const generatedAttachmentFileName = makeFileName({
      fileBaseName: generatedAttachmentFileBaseName,
      fileExtension: attachmentFile.extension
    });

    const attachmentFolderFullPath = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
      actionContext: ActionContext.ExternalAttachmentCreated,
      attachmentFileName: generatedAttachmentFileName,
      attachmentFileStats: attachmentFile.stat,
      notePath: noteFile.path,
      readAttachmentFileContent
    });

    /*
     * Check the un-deduplicated path first. `getAvailablePath` counts the file being moved as an
     * occupant of its own path, so asking it about an attachment that is ALREADY where the templates
     * put it hands back a ` 1` suffix — and the move would then rename a correct file on every
     * creation event.
     */
    const properAttachmentPath = join(attachmentFolderFullPath, generatedAttachmentFileName);
    if (properAttachmentPath === attachmentFile.path) {
      return;
    }

    const newAttachmentPath = this.app.vault.getAvailablePath(
      join(attachmentFolderFullPath, generatedAttachmentFileBaseName),
      attachmentFile.extension
    );

    /*
     * `renameFile` will not create the destination folder, and the template routinely resolves to one
     * that does not exist yet — the creating plugin wrote into a folder of its own choosing.
     */
    const newAttachmentFolderPath = dirname(newAttachmentPath);
    if (!await this.app.vault.exists(newAttachmentFolderPath)) {
      await createFolderSafe(this.app, newAttachmentFolderPath);
    }

    const oldAttachmentPath = attachmentFile.path;
    await this.app.fileManager.renameFile(attachmentFile, newAttachmentPath);
    this.repointUnsavedEditorLinks(oldAttachmentPath, newAttachmentPath, attachmentFile, noteFile);
  }

  /**
   * Repoints links the creating plugin inserted into an editor that has not been saved yet.
   *
   * `fileManager.renameFile` rewrites every reference the metadata cache knows about, but a plugin that
   * inserts its embed straight into the editor the moment its write resolves leaves that text unsaved,
   * and therefore unindexed. The rename cannot see it, so the note is left pointing at a path that no
   * longer exists — verified against a real Obsidian, not assumed. This is the same gap the *Paste
   * image rename* plugin closes by rewriting the current editor line by hand; every open markdown
   * editor is checked here, since the note being written into need not be the focused one.
   *
   * Runs AFTER the rename, which is what makes the timing work: by then the creating plugin has had its
   * turn to insert.
   */
  private repointUnsavedEditorLinks(oldPath: string, newPath: string, attachmentFile: TFile, noteFile: TFile): void {
    /*
     * Four spellings, longest first — replacing the full path before the bare file name matters, since
     * the former contains the latter.
     *
     * The bare file name is not an edge case: Obsidian's shortest-form links are the DEFAULT, and Media
     * Extended inserts exactly that — `![[<file name>|<alias>]]`, no folder at all — so a full-path-only
     * rewrite left the reporter's note pointing at a file that no longer exists. Confirmed by driving
     * the real plugin, which is the only reason it was caught.
     */
    const newLinkText = this.app.metadataCache.fileToLinktext(attachmentFile, noteFile.path);
    const oldFileName = basename(oldPath);
    /*
     * An ORDERED list, not a `Map` — the order is part of the behavior, and a sorted-map lint rule would
     * silently reorder it into a bug.
     *
     * A Markdown link percent-encodes the path where a wikilink does not, so both spellings are fixed.
     */
    const replacements: readonly (readonly [string, string])[] = [
      [encodeURI(oldPath), encodeURI(newPath)],
      [oldPath, newPath],
      [encodeURI(oldFileName), encodeURI(newLinkText)],
      [oldFileName, newLinkText]
    ];

    for (const leaf of this.app.workspace.getLeavesOfType(ViewType.Markdown)) {
      const { editor } = leaf.view as MarkdownView;
      const changes: EditorChange[] = [];

      for (let line = 0; line < editor.lineCount(); line++) {
        const text = editor.getLine(line);
        let newText = text;
        for (const [from, to] of replacements) {
          newText = newText.split(from).join(to);
        }

        if (newText !== text) {
          changes.push({
            from: { ch: 0, line },
            text: newText,
            to: { ch: text.length, line }
          });
        }
      }

      if (changes.length > 0) {
        // A line-scoped transaction rather than `setValue`, so the cursor and the undo history survive.
        editor.transaction({ changes });
      }
    }
  }
}
