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
import {
  convertAsyncToSync,
  setTimeoutAsync
} from 'obsidian-dev-utils/async';
import { printError } from 'obsidian-dev-utils/error';
import {
  splitSubpath,
  updateLink
} from 'obsidian-dev-utils/obsidian/link';
import {
  parseLinks,
  toParseLinkReference
} from 'obsidian-dev-utils/obsidian/parse-link';
import { createFolderSafe } from 'obsidian-dev-utils/obsidian/vault';
import {
  basename,
  dirname,
  join,
  makeFileName
} from 'obsidian-dev-utils/path';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { TokenValidator } from './token-validator.ts';

import { foreignWriteRegistry } from './foreign-write-registry.ts';
import { RenameAttachmentsCreatedByOtherPluginsMode } from './plugin-settings.ts';
import { selfWriteRegistry } from './self-write-registry.ts';
import { Substitutions } from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';

const FRESHLY_CREATED_THRESHOLD_IN_MILLISECONDS = 10_000;
const NOTE_REFERENCE_POLL_INTERVAL_IN_MILLISECONDS = 100;
const NOTE_REFERENCE_WAIT_IN_MILLISECONDS = 5000;

interface ExternallyCreatedAttachmentHandlerComponentConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
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
 * rename* plugin does, and the catch itself stays GENERAL — nothing here is keyed to any one plugin.
 *
 * WHICH foreign writes are taken is the user's choice, though (issue #77): all of them, only a named set,
 * or all but a named set. That needs the creating plugin identified, which `vault.on('create')` cannot do —
 * `WriteAttributionPatchComponent` records it at the write instead, and this handler reads it back out of
 * {@link foreignWriteRegistry}.
 *
 * Off by default: it reacts to writes the plugin did not make, so it must never change behavior on
 * upgrade.
 */
export class ExternallyCreatedAttachmentHandlerComponent extends Component {
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: ExternallyCreatedAttachmentHandlerComponentConstructorParams) {
    super();
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
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
    const { settings } = this.pluginSettingsComponent;
    if (settings.renameAttachmentsCreatedByOtherPluginsMode === RenameAttachmentsCreatedByOtherPluginsMode.None) {
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

    if (this.handedOverSettingsComponent.isPathIgnored(attachmentFile.path)) {
      return;
    }

    /*
     * Consumed after the cheap guards, so a creation that was never a candidate does not throw away the
     * attribution of a path that is about to be written again. Whatever is never consumed expires on its
     * own after a minute.
     *
     * `null` — nothing recorded the write — is a real answer, not a failure: Obsidian core, a sync client
     * and a raw `fs` write all leave no plugin on the stack. The setting treats it as "not one of the
     * listed plugins", which is what makes both list modes read the way their names promise.
     */
    const creatingPluginId = foreignWriteRegistry.consume(attachmentFile.path);
    if (!settings.shouldRenameAttachmentCreatedByPlugin(creatingPluginId)) {
      return;
    }

    const noteFile = this.findNoteFile();
    // The templates are relative to a note. Without one there is nothing to resolve them against.
    if (!noteFile) {
      return;
    }

    if (this.handedOverSettingsComponent.isPathIgnored(noteFile.path)) {
      return;
    }

    if (!await this.waitForNoteReference(attachmentFile, noteFile)) {
      return;
    }

    try {
      await this.moveToProperPath(attachmentFile, noteFile);
    } catch (error) {
      printError(error);
    }
  }

  /**
   * Tells whether any note links to the file right now.
   *
   * An open editor is read first, since that is where a creating plugin's freshly inserted embed sits before
   * the note is saved and indexed. A link in an editor with no file of its own is resolved against the note
   * the templates are evaluated for.
   *
   * @param attachmentFile - The file another plugin created.
   * @param noteFile - The note the templates are evaluated against.
   * @returns Whether a note links to the file.
   */
  private isReferencedByNote(attachmentFile: TFile, noteFile: TFile): boolean {
    for (const leaf of this.app.workspace.getLeavesOfType(ViewType.Markdown)) {
      const view = leaf.view as MarkdownView;
      const sourcePath = view.file?.path ?? noteFile.path;
      const text = view.editor.getValue();
      if (parseLinks(text).some((parseLinkResult) => !parseLinkResult.isExternal && isLinkTo(parseLinkResult.url, attachmentFile.path, sourcePath))) {
        return true;
      }
    }

    return Object.values(this.app.metadataCache.resolvedLinks).some((links) => Object.hasOwn(links, attachmentFile.path));
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
    this.repointUnsavedEditorLinks(oldAttachmentPath, attachmentFile, noteFile);
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
   * Each LINK is resolved against the note and regenerated whole, rather than the old path being
   * substituted as text. Text substitution is what issue #82 reported: a link spelled relative to the
   * note (`./assets/<note>/<file>`) contains the vault path nowhere, so only its bare file name matched —
   * and it was swapped for a link text that, under a relative or absolute link format, carries the
   * folder again, so the link came out as `./assets/<note>/assets/<note>/<file>`.
   *
   * Runs AFTER the rename, which is what makes the timing work: by then the creating plugin has had its
   * turn to insert.
   */
  private repointUnsavedEditorLinks(oldPath: string, attachmentFile: TFile, noteFile: TFile): void {
    for (const leaf of this.app.workspace.getLeavesOfType(ViewType.Markdown)) {
      const { editor } = leaf.view as MarkdownView;
      const changes: EditorChange[] = [];

      for (let line = 0; line < editor.lineCount(); line++) {
        const text = editor.getLine(line);
        let newText = '';
        let lastOffset = 0;

        for (const parseLinkResult of parseLinks(text)) {
          if (parseLinkResult.isExternal || !isLinkTo(parseLinkResult.url, oldPath, noteFile.path)) {
            continue;
          }

          newText += text.slice(lastOffset, parseLinkResult.startOffset);
          newText += updateLink({
            app: this.app,
            link: toParseLinkReference({ content: text, parseLinkResult }),
            newSourcePathOrFile: noteFile,
            newTargetPathOrFile: attachmentFile,
            oldTargetPathOrFile: oldPath
          });
          lastOffset = parseLinkResult.endOffset;
        }

        if (lastOffset === 0) {
          continue;
        }

        newText += text.slice(lastOffset);
        changes.push({
          from: { ch: 0, line },
          text: newText,
          to: { ch: text.length, line }
        });
      }

      if (changes.length > 0) {
        // A line-scoped transaction rather than `setValue`, so the cursor and the undo history survive.
        editor.transaction({ changes });
      }
    }
  }

  /**
   * Waits for a note to link to the file, which is what makes it an attachment at all (issue #88).
   *
   * A plugin writes files for its own use too — Lingua Study keeps a transcript JSON under its own folder and
   * reads it back from that path — and moving one of those breaks that plugin. What tells the two apart is not
   * the extension, the folder or the creating plugin but whether a note refers to the file: a user's attachment
   * is embedded or linked, a plugin's private data is not. So a file nothing links to is left where it was
   * written.
   *
   * The creating plugin inserts its embed AFTER its write resolves, which is after `create` fired, so the link
   * is waited for rather than expected at once. Media Extended inserts within milliseconds; the window only
   * delays the answer for a file that is never linked, and that file is never moved anyway.
   *
   * @param attachmentFile - The file another plugin created.
   * @param noteFile - The note the templates are evaluated against.
   * @returns Whether a note linked to the file within the window.
   */
  private async waitForNoteReference(attachmentFile: TFile, noteFile: TFile): Promise<boolean> {
    const deadline = Date.now() + NOTE_REFERENCE_WAIT_IN_MILLISECONDS;
    for (;;) {
      if (this.isReferencedByNote(attachmentFile, noteFile)) {
        return true;
      }

      if (Date.now() >= deadline) {
        return false;
      }

      await setTimeoutAsync(NOTE_REFERENCE_POLL_INTERVAL_IN_MILLISECONDS);
    }
  }
}

/**
 * Tells whether a link written in the note resolves to `targetPath`.
 *
 * The file has already moved, so Obsidian's own resolver cannot answer — it would find nothing at the
 * old path. The spellings Obsidian accepts are checked instead: relative to the note's folder (which
 * covers `./` and `../`), vault-absolute (with or without a leading `/`), and the bare file name, which
 * is Obsidian's DEFAULT shortest form and exactly what Media Extended inserts.
 */
function isLinkTo(url: string, targetPath: string, notePath: string): boolean {
  const { linkPath } = splitSubpath(url);
  if (!linkPath) {
    return false;
  }

  if (linkPath.startsWith('/')) {
    return linkPath.slice(1) === targetPath;
  }

  return join(dirname(notePath), linkPath) === targetPath
    || linkPath === targetPath
    || linkPath === basename(targetPath);
}
