import type {
  App,
  TAbstractFile,
  TFile,
  TFolder
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';

import {
  setIcon,
  Vault
} from 'obsidian';
import { findAttachmentUnitFolderPath } from 'obsidian-dev-utils/obsidian/attachment-unit-folder';
import { getCanvasReferences } from 'obsidian-dev-utils/obsidian/canvas';
import {
  isCanvasFile,
  isFile,
  isFolder,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { appendCodeBlock } from 'obsidian-dev-utils/obsidian/html-element';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { extractLinkFile } from 'obsidian-dev-utils/obsidian/link';
import { loop } from 'obsidian-dev-utils/obsidian/loop';
import {
  getBacklinksForFileSafe,
  getCacheSafe,
  getLinks
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { addToQueue } from 'obsidian-dev-utils/obsidian/queue';
import {
  cleanupEmptyFolders,
  trashSafe
} from 'obsidian-dev-utils/obsidian/vault';
import { dirname } from 'obsidian-dev-utils/path';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { checkIsAttachmentUnitFolder } from './attachment-unit-folder-designation.ts';
import { ActionContext } from './token-evaluator-context.ts';

// The note's attachment folder path template rarely depends on the attachment file name (the default
// `./assets/${noteFileName}` does not), so a placeholder name is enough to resolve the folder to scan.
const PLACEHOLDER_ATTACHMENT_FILE_NAME = 'unused-attachment';

/**
 * How many paths the confirmation dialog names before summarizing the rest. Enough to recognize what
 * the sweep found, short enough that the buttons stay on screen.
 */
const CONFIRM_LIST_LIMIT = 50;

interface UnusedAttachmentsRemoverConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly pluginName: string;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
 * What one note's scan contributes to the sweep.
 *
 * Two collections rather than one, because a designated attachment unit folder is deleted as a FOLDER:
 * listing its members individually would trash each of them and then their parent, and the second
 * delete of the same path throws.
 */
interface UnusedAttachmentsScanResult {
  /**
   * Attachment files that are unused on their own — every candidate belonging to no attachment unit
   * folder, plus those of a unit the unit rule deliberately stepped away from.
   */
  readonly unusedAttachments: TFile[];

  /**
   * Attachment unit folders nothing outside them references, to be trashed whole.
   */
  readonly unusedUnitFolders: TFolder[];
}

export class UnusedAttachmentsRemover {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly pluginName: string;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: UnusedAttachmentsRemoverConstructorParams) {
    this.abortSignalComponent = params.abortSignalComponent;
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.pluginName = params.pluginName;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public deleteUnusedAttachmentsEntireVault(): void {
    addToQueue({
      abortSignal: this.abortSignalComponent.abortSignal,
      operationFunction: (abortSignal) => this.deleteUnusedAttachmentsInAbstractFilesImpl([this.app.vault.getRoot()], abortSignal),
      operationName: t(($) => $.commands.deleteUnusedAttachmentsEntireVault),
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
    });
  }

  public deleteUnusedAttachmentsInAbstractFiles(abstractFiles: TAbstractFile[]): void {
    addToQueue({
      abortSignal: this.abortSignalComponent.abortSignal,
      operationFunction: (abortSignal) => this.deleteUnusedAttachmentsInAbstractFilesImpl(abstractFiles, abortSignal),
      operationName: t(($) => $.menuItems.deleteUnusedAttachmentsInFile),
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
    });
  }

  /**
   * Whether anything OUTSIDE the attachment unit folder still references a file inside it.
   *
   * The `outside` qualifier is the whole rule. A member linking a sibling is the unit describing
   * itself, and counting that as use makes a self-referencing unit immortal — a drawing next to the
   * images it embeds gives every one of those images a backlink forever.
   *
   * The scanning note is deliberately NOT filtered out the way the per-file rule filters it. It sits
   * outside the unit, so its link into the unit is a genuine outside reference; the per-file rule
   * reaches that same answer earlier, by dropping the note's referenced files from the candidates.
   */
  private async checkIsUnitFolderReferencedFromOutside(unitFolderPath: string, unitFiles: TFile[], abortSignal: AbortSignal): Promise<boolean> {
    const insidePathPrefix = `${unitFolderPath}/`;

    for (const unitFile of unitFiles) {
      abortSignal.throwIfAborted();
      const backlinks = await getBacklinksForFileSafe({
        app: this.app,
        pathOrFile: unitFile,
        timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
      });

      const outsideBacklinks = backlinks.keys().filter((backlink) => !backlink.startsWith(insidePathPrefix) && !this.pluginSettingsComponent.settings.isExcludedFromMultipleNotesCheck(backlink));
      if (outsideBacklinks.length > 0) {
        return true;
      }
    }

    return false;
  }

  private async deleteUnusedAttachmentsInAbstractFilesImpl(abstractFiles: TAbstractFile[], abortSignal: AbortSignal): Promise<void> {
    abortSignal.throwIfAborted();

    const noteFilesSet = new Set<TFile>();
    for (const abstractFile of abstractFiles) {
      if (isFile(abstractFile) && isNote(abstractFile)) {
        noteFilesSet.add(abstractFile);
      }

      if (isFolder(abstractFile)) {
        Vault.recurseChildren(abstractFile, (child) => {
          if (isFile(child) && isNote(child)) {
            noteFilesSet.add(child);
          }
        });
      }
    }

    const noteFiles = [...noteFilesSet].sort((a, b) => a.path.localeCompare(b.path));

    // Compute the full set of attachments to trash BEFORE deleting anything, so the confirmation
    // Modal lists exactly what will be removed.
    const unusedAttachments = new Set<TFile>();
    // Keyed by path, so two notes reaching the same attachment unit folder queue it once.
    const unusedUnitFolderByPath = new Map<string, TFolder>();

    const scanNote = async (noteFile: TFile): Promise<void> => {
      abortSignal.throwIfAborted();
      if (this.handedOverSettingsComponent.isPathIgnored(noteFile.path)) {
        console.warn(`Cannot delete unused attachments as note path is ignored: ${noteFile.path}.`);
        return;
      }

      const scanResult = await this.findUnusedAttachments(noteFile, abortSignal);
      for (const attachment of scanResult.unusedAttachments) {
        unusedAttachments.add(attachment);
      }

      for (const unitFolder of scanResult.unusedUnitFolders) {
        unusedUnitFolderByPath.set(unitFolder.path, unitFolder);
      }
    };

    /*
     * The scan is the slow half, and vault-wide it walks every note in the vault while looking up the
     * backlinks of every attachment it meets — minutes on a large vault, with nothing on screen. The
     * progress notice is what makes that survivable, and what gives the user somewhere to cancel.
     *
     * ONLY for a bulk scope, though. `loop` keeps its notice up for a minimum of two seconds
     * (`noticeMinTimeoutInMilliseconds`, awaited before it hides), so running it for a single note
     * would turn an instant command into a ~2.5 s one with a progress bar counting to 1. The scope the
     * user chose is exactly the right signal: one note is never worth reporting progress on.
     */
    if (noteFiles.length > 1) {
      await loop({
        abortSignal,
        buildNoticeMessage: ({ item, iterationString }) => t(($) => $.deleteUnusedAttachments.progressBar.message, { iterationString, noteFilePath: item.path }),
        items: noteFiles,
        pluginNoticeComponent: this.pluginNoticeComponent,
        processItem: scanNote,
        progressBarTitle: `${this.pluginName}: ${t(($) => $.deleteUnusedAttachments.progressBar.title)}`,
        shouldContinueOnError: true,
        shouldShowProgressBar: true
      });
    } else {
      for (const noteFile of noteFiles) {
        await scanNote(noteFile);
      }
    }

    const unitFoldersToDelete = [...unusedUnitFolderByPath.values()].sort((a, b) => a.path.localeCompare(b.path));

    /*
     * Belt and braces. Every note reaching the same unit folder judges it the same way — the rule
     * reads the backlink index, not anything note-local — so a member should never be listed loose
     * beside its own folder. But the two answers are computed per note, and trashing a file and then
     * the folder containing it is a double delete of the same path: the second throws `ENOENT` from
     * the rename into `.trash`, taking the rest of the sweep with it. The folder already takes
     * everything inside it, so dropping the member costs nothing.
     */
    const attachmentsToDelete = [...unusedAttachments]
      .filter((attachment) => unitFoldersToDelete.every((unitFolder) => !attachment.path.startsWith(`${unitFolder.path}/`)))
      .sort((a, b) => a.path.localeCompare(b.path));

    if (attachmentsToDelete.length === 0 && unitFoldersToDelete.length === 0) {
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.noUnusedAttachments));
      return;
    }

    const isConfirmed = await confirm({
      app: this.app,
      cancelButtonText: t(($) => $.obsidianDevUtils.buttons.cancel),
      message: createFragment((f) => {
        if (attachmentsToDelete.length > 0) {
          f.appendText(t(($) => $.deleteUnusedAttachments.confirm.part1));
          f.createEl('br');
          /*
           * The COUNT, always, and before the list. Vault-wide this dialog can be asked to name
           * thousands of files, at which point an unbounded list is not a safety check — it is a wall
           * the user scrolls past. The number is the part they can actually weigh.
           */
          f.createEl('strong', { text: t(($) => $.deleteUnusedAttachments.confirm.count, { count: attachmentsToDelete.length }) });
          f.createEl('br');
          appendPathList(f, attachmentsToDelete.map((attachment) => attachment.path));
        }

        /*
         * Unit folders get their own heading and list rather than being folded in with the files. A
         * designation can be written broadly — designating `assets` makes `assets` itself the unit —
         * and this dialog is the only thing standing between that and a folder-sized delete, so it
         * has to say plainly that a whole folder goes, and name it.
         */
        if (unitFoldersToDelete.length > 0) {
          f.appendText(t(($) => $.deleteUnusedAttachments.confirm.partUnitFolders));
          f.createEl('br');
          f.createEl('strong', { text: t(($) => $.deleteUnusedAttachments.confirm.unitFolderCount, { count: unitFoldersToDelete.length }) });
          f.createEl('br');
          appendPathList(f, unitFoldersToDelete.map((unitFolder) => unitFolder.path));
        }

        f.createEl('br');
        f.appendText(t(($) => $.deleteUnusedAttachments.confirm.part2));
      }),
      okButtonText: t(($) => $.obsidianDevUtils.buttons.ok),
      title: createFragment((f) => {
        setIcon(f.createSpan(), 'lucide-alert-triangle');
        f.appendText(' ');
        f.appendText(t(($) => $.menuItems.deleteUnusedAttachmentsInFile));
      })
    });

    if (!isConfirmed) {
      abortSignal.throwIfAborted();
      return;
    }

    const oldParentFolderPaths = new Set<string>();

    // Folders first: each one takes everything inside it, so nothing below is reached twice.
    for (const unitFolder of unitFoldersToDelete) {
      abortSignal.throwIfAborted();
      oldParentFolderPaths.add(dirname(unitFolder.path));
      await trashSafe(this.app, unitFolder);
    }

    for (const attachment of attachmentsToDelete) {
      abortSignal.throwIfAborted();
      oldParentFolderPaths.add(dirname(attachment.path));
      await trashSafe(this.app, attachment);
    }

    await cleanupEmptyFolders({
      app: this.app,
      emptyFolderBehavior: this.handedOverSettingsComponent.settings.emptyFolderBehavior,
      folderPaths: [...oldParentFolderPaths]
    });
  }

  /**
   * Resolves the attachment unit folder an attachment belongs to.
   *
   * Read back through the PUBLISHED designation rather than straight off the settings, so this sweep,
   * the collecting commands and the plugin that owns the delete interception all decide from one
   * answer. Two of them deciding separately what a single attachment is would leave a folder kept
   * whole by one and torn apart by the other.
   */
  private findUnitFolderPath(attachmentPath: string): null | string {
    return findAttachmentUnitFolderPath({
      attachmentPath,
      checkIsAttachmentUnitFolder: (folderPath) =>
        checkIsAttachmentUnitFolder({
          folderPath,
          vault: this.app.vault
        })
    });
  }

  private async findUnusedAttachments(note: TFile, abortSignal: AbortSignal): Promise<UnusedAttachmentsScanResult> {
    const cache = await getCacheSafe(this.app, note);
    abortSignal.throwIfAborted();
    if (!cache) {
      return {
        unusedAttachments: [],
        unusedUnitFolders: []
      };
    }

    const references = isCanvasFile(note) ? await getCanvasReferences(this.app, note) : getLinks({ cache });
    abortSignal.throwIfAborted();

    const referencedAttachmentPaths = new Set<string>();
    for (const reference of references) {
      const referencedFile = extractLinkFile({
        app: this.app,
        link: reference,
        shouldAllowNonExistingFile: true,
        sourcePathOrFile: note
      });
      if (referencedFile) {
        referencedAttachmentPaths.add(referencedFile.path);
      }
    }

    const attachmentFolderPath = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
      actionContext: ActionContext.Unknown,
      attachmentFileName: PLACEHOLDER_ATTACHMENT_FILE_NAME,
      notePath: note.path
    });
    abortSignal.throwIfAborted();

    const attachmentFolder = this.app.vault.getFolderByPath(attachmentFolderPath);
    if (!attachmentFolder) {
      return {
        unusedAttachments: [],
        unusedUnitFolders: []
      };
    }

    const candidates: TFile[] = [];
    Vault.recurseChildren(attachmentFolder, (child) => {
      if (isFile(child) && !this.pluginSettingsComponent.isNoteEx(child) && !referencedAttachmentPaths.has(child.path)) {
        candidates.push(child);
      }
    });

    /*
     * Bucket the candidates by the attachment unit folder they belong to, so a designated folder is
     * judged as ONE attachment rather than file by file. Everything outside any unit keeps the
     * per-file rule untouched — which is every candidate there is for a user who designates none.
     */
    const perFileCandidates: TFile[] = [];
    const candidatesByUnitFolderPath = new Map<string, TFile[]>();

    for (const candidate of candidates) {
      const unitFolderPath = this.findUnitFolderPath(candidate.path);
      if (unitFolderPath === null) {
        perFileCandidates.push(candidate);
        continue;
      }

      const bucket = candidatesByUnitFolderPath.get(unitFolderPath);
      if (bucket) {
        bucket.push(candidate);
      } else {
        candidatesByUnitFolderPath.set(unitFolderPath, [candidate]);
      }
    }

    const unusedUnitFolders: TFolder[] = [];

    for (const [unitFolderPath, unitCandidates] of candidatesByUnitFolderPath) {
      abortSignal.throwIfAborted();

      const unitFolder = this.app.vault.getFolderByPath(unitFolderPath);
      if (!unitFolder) {
        // The designation resolved to a folder the vault does not have, so there is no unit to judge.
        perFileCandidates.push(...unitCandidates);
        continue;
      }

      /*
       * EVERY file in the unit, not just the candidates. The members this note references were
       * filtered out of the candidates upstream, and they are exactly the evidence that the unit is
       * still in use.
       */
      const unitFiles: TFile[] = [];
      Vault.recurseChildren(unitFolder, (child) => {
        if (isFile(child)) {
          unitFiles.push(child);
        }
      });

      /*
       * A real note inside the unit takes the whole folder off the table. Trashing a note is never
       * something an attachment sweep should do on the user's behalf, so its members fall back to the
       * per-file rule, which can only ever reach attachments. Note that this also spares a unit that
       * happens to contain the scanning note itself.
       */
      if (unitFiles.some((unitFile) => this.pluginSettingsComponent.isNoteEx(unitFile))) {
        perFileCandidates.push(...unitCandidates);
        continue;
      }

      if (await this.checkIsUnitFolderReferencedFromOutside(unitFolder.path, unitFiles, abortSignal)) {
        /*
         * Kept WHOLE — members nothing references included. A unit travels as one attachment, so it
         * dies as one too; deleting the unreferenced half of a live unit is precisely the torn-apart
         * attachment the designation exists to prevent.
         */
        continue;
      }

      unusedUnitFolders.push(unitFolder);
    }

    const unusedAttachments: TFile[] = [];
    for (const candidate of perFileCandidates) {
      abortSignal.throwIfAborted();
      const backlinks = await getBacklinksForFileSafe({
        app: this.app,
        pathOrFile: candidate,
        timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
      });
      // An attachment is unused only when no OTHER note still references it. Notes matching the
      // Multiple-notes-check exclusion are ignored, mirroring the Collect/Move commands, so a shared
      // Attachment is never trashed.
      const relevantBacklinks = backlinks.keys().filter((backlink) => backlink !== note.path && !this.pluginSettingsComponent.settings.isExcludedFromMultipleNotesCheck(backlink));
      if (relevantBacklinks.length === 0) {
        unusedAttachments.push(candidate);
      }
    }

    return {
      unusedAttachments,
      unusedUnitFolders
    };
  }
}

/**
 * Renders a capped, code-formatted list of vault paths into the confirmation dialog.
 *
 * @param parentEl - The fragment to append the list to.
 * @param paths - The paths to list.
 */
function appendPathList(parentEl: DocumentFragment, paths: string[]): void {
  parentEl.createEl('ul', {}, (ul) => {
    for (const path of paths.slice(0, CONFIRM_LIST_LIMIT)) {
      ul.createEl('li', {}, (li) => {
        appendCodeBlock(li, path);
      });
    }
    if (paths.length > CONFIRM_LIST_LIMIT) {
      ul.createEl('li', {
        text: t(($) => $.deleteUnusedAttachments.confirm.andMore, { count: paths.length - CONFIRM_LIST_LIMIT })
      });
    }
  });
}
