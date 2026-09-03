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

/**
 * What one note's scan contributes, plus what it saw.
 *
 * The references are reported back because the sweep needs them after the note is done with them: they are
 * the standing evidence that SOMETHING still points at a file, for the attachment-driven pass that has no
 * note of its own to ask.
 */
interface NoteScanResult extends UnusedAttachmentsScanResult {
  /**
   * Every existing file this note references.
   */
  readonly referencedAttachmentPaths: ReadonlySet<string>;
}

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
 * Parameters for {@link UnusedAttachmentsRemover.deleteUnusedAttachmentsInAbstractFilesImpl}.
 */
interface UnusedAttachmentsRemoverDeleteUnusedAttachmentsInAbstractFilesImplParams {
  /**
   * Aborts the sweep.
   */
  readonly abortSignal: AbortSignal;

  /**
   * The scope to sweep.
   */
  readonly abstractFiles: TAbstractFile[];

  /**
   * Whether the attachment-driven pass runs alongside the note-driven one.
   *
   * Only the vault-wide command sets it, because only a scan that read every note in the vault can tell
   * "nothing references this" from "nothing I happened to look at references this".
   */
  readonly shouldScanOrphanAttachments: boolean;
}

/**
 * Parameters for {@link UnusedAttachmentsRemover.judgeCandidates}.
 */
interface UnusedAttachmentsRemoverJudgeCandidatesParams {
  /**
   * Aborts the scan.
   */
  readonly abortSignal: AbortSignal;

  /**
   * The attachment files to judge.
   */
  readonly candidates: TFile[];

  /**
   * The vault-relative path of the note that produced the candidates, or `null` when nothing did.
   */
  readonly notePath: null | string;

  /**
   * Whether the per-file half reports its own progress.
   *
   * The note-driven pass already runs under a progress bar counting notes, so a second one nested inside it
   * would fight the first for the same notice. The attachment-driven pass has no outer bar, and vault-wide
   * it is the slow half, so it needs one.
   */
  readonly shouldShowProgressBar: boolean;
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
      operationFunction: (abortSignal) =>
        this.deleteUnusedAttachmentsInAbstractFilesImpl({
          abortSignal,
          abstractFiles: [this.app.vault.getRoot()],
          shouldScanOrphanAttachments: true
        }),
      operationName: t(($) => $.commands.deleteUnusedAttachmentsEntireVault),
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
    });
  }

  public deleteUnusedAttachmentsInAbstractFiles(abstractFiles: TAbstractFile[]): void {
    addToQueue({
      abortSignal: this.abortSignalComponent.abortSignal,
      operationFunction: (abortSignal) =>
        this.deleteUnusedAttachmentsInAbstractFilesImpl({
          abortSignal,
          abstractFiles,
          /*
           * The orphan pass is VAULT-WIDE ONLY, and that is a safety requirement rather than a scoping
           * preference. Its evidence that nothing owns a file is "no note in the scan referenced it, and it
           * has no backlinks" — and the first half is only trustworthy when the scan read every note in the
           * vault. Under a narrower scope a canvas outside the selection could be the sole thing embedding
           * a file inside it, and a canvas's links are not in the backlink index (which is exactly why
           * `findUnusedAttachments` reads them out of the canvas JSON instead), so that file would be
           * judged ownerless and trashed.
           */
          shouldScanOrphanAttachments: false
        }),
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

  /**
   * Collects every existing file a note references.
   *
   * Split out because the sweep needs this answer from notes it does NOT scan — one whose path is ignored
   * still keeps its attachments alive, and the attachment-driven pass has no other way to learn that.
   *
   * Canvas is read out of its JSON rather than out of the metadata cache, because Obsidian does not index a
   * canvas's embeds into the per-file cache at all. That is also why this set matters so much: the same gap
   * means those embeds are missing from the backlink index, so a backlink lookup alone would call such a
   * file unreferenced.
   *
   * @param note - The note to read.
   * @param abortSignal - Aborts the read.
   * @returns The vault-relative paths the note references.
   */
  private async collectReferencedAttachmentPaths(note: TFile, abortSignal: AbortSignal): Promise<Set<string>> {
    const referencedAttachmentPaths = new Set<string>();

    const cache = await getCacheSafe(this.app, note);
    abortSignal.throwIfAborted();
    if (!cache) {
      return referencedAttachmentPaths;
    }

    const references = isCanvasFile(note) ? await getCanvasReferences(this.app, note) : getLinks({ cache });
    abortSignal.throwIfAborted();

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

    return referencedAttachmentPaths;
  }

  private async deleteUnusedAttachmentsInAbstractFilesImpl(params: UnusedAttachmentsRemoverDeleteUnusedAttachmentsInAbstractFilesImplParams): Promise<void> {
    const abortSignal = params.abortSignal;
    abortSignal.throwIfAborted();

    const shouldScanOrphanAttachments = params.shouldScanOrphanAttachments;

    const noteFilesSet = new Set<TFile>();
    const orphanCandidateFilesSet = new Set<TFile>();

    const collectFile = (file: TFile): void => {
      if (isNote(file)) {
        noteFilesSet.add(file);
      }

      /*
       * The mode check comes first so a user who never opted in pays nothing — it short-circuits before
       * `isNoteEx`, which asks the other plugin whether the extension is treated as an attachment.
       */
      if (
        shouldScanOrphanAttachments
        && this.pluginSettingsComponent.settings.isOrphanAttachmentScanCandidate(file.path)
        && !this.pluginSettingsComponent.isNoteEx(file)
      ) {
        orphanCandidateFilesSet.add(file);
      }
    };

    for (const abstractFile of params.abstractFiles) {
      if (isFile(abstractFile)) {
        collectFile(abstractFile);
      }

      if (isFolder(abstractFile)) {
        Vault.recurseChildren(abstractFile, (child) => {
          if (isFile(child)) {
            collectFile(child);
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

    /**
     * Every attachment path SOME scanned note still references, accumulated across the whole sweep.
     *
     * The note-driven pass drops these from its own candidates before judging anything, so for a file
     * referenced by a link the backlink index does not carry — a canvas embed, which is why
     * {@link findUnusedAttachments} reads canvas references out of the JSON rather than out of the cache —
     * that filter is the ONLY thing keeping it alive. The orphan pass has no note and therefore no such
     * filter, so without this memo it would look the file up by backlinks, find none, and trash it.
     */
    const referencedAttachmentPaths = new Set<string>();

    const scanNote = async (noteFile: TFile): Promise<void> => {
      abortSignal.throwIfAborted();
      if (this.handedOverSettingsComponent.isPathIgnored(noteFile.path)) {
        console.warn(`Cannot delete unused attachments as note path is ignored: ${noteFile.path}.`);

        /*
         * Skipped for JUDGING, still read for EVIDENCE. An ignored note is one the sweep must not act on,
         * not one whose links stop counting — and the attachment-driven pass below would otherwise treat
         * everything it holds alive as ownerless.
         */
        if (shouldScanOrphanAttachments) {
          for (const referencedAttachmentPath of await this.collectReferencedAttachmentPaths(noteFile, abortSignal)) {
            referencedAttachmentPaths.add(referencedAttachmentPath);
          }
        }

        return;
      }

      const scanResult = await this.findUnusedAttachments(noteFile, abortSignal);
      for (const attachment of scanResult.unusedAttachments) {
        unusedAttachments.add(attachment);
      }

      for (const unitFolder of scanResult.unusedUnitFolders) {
        unusedUnitFolderByPath.set(unitFolder.path, unitFolder);
      }

      for (const referencedAttachmentPath of scanResult.referencedAttachmentPaths) {
        referencedAttachmentPaths.add(referencedAttachmentPath);
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

    /*
     * The attachment-driven pass, for the files the note-driven one structurally cannot reach: an
     * attachment folder is visited only through the note that owns it, so when that note is gone — removed
     * by a sync client rather than by Obsidian, so no delete event ever fired either — nothing in the vault
     * resolves to the folder and it is never scanned.
     *
     * It runs AFTER the note loop on purpose. Everything the notes referenced is known by now, and that set
     * is what stands in for the per-note reference filter this pass does not have.
     */
    const orphanCandidates = [...orphanCandidateFilesSet]
      .filter((candidate) => {
        if (referencedAttachmentPaths.has(candidate.path)) {
          return false;
        }

        // Already judged by the note that owns it, whose answer is the better-informed one.
        if (unusedAttachments.has(candidate)) {
          return false;
        }

        if (this.handedOverSettingsComponent.isPathIgnored(candidate.path)) {
          console.warn(`Cannot delete unused attachment as its path is ignored: ${candidate.path}.`);
          return false;
        }

        return true;
      })
      .sort((a, b) => a.path.localeCompare(b.path));

    if (orphanCandidates.length > 0) {
      const orphanScanResult = await this.judgeCandidates({
        abortSignal,
        candidates: orphanCandidates,
        notePath: null,
        shouldShowProgressBar: true
      });

      for (const attachment of orphanScanResult.unusedAttachments) {
        unusedAttachments.add(attachment);
      }

      for (const unitFolder of orphanScanResult.unusedUnitFolders) {
        unusedUnitFolderByPath.set(unitFolder.path, unitFolder);
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

    /**
     * Records the folder a deleted path came out of, so it can be tidied up if it is left empty.
     *
     * The vault ROOT is deliberately never recorded. Only the attachment-driven pass can reach a file
     * sitting at the top level of the vault, and `dirname` answers `.` for one — a path no folder in the
     * vault has, and one the empty-folder cleanup walks UPWARDS from with no root guard of its own.
     *
     * @param path - The vault-relative path that was deleted.
     */
    function recordOldParentFolderPath(path: string): void {
      const oldParentFolderPath = dirname(path);
      if (oldParentFolderPath === '.' || oldParentFolderPath === '') {
        return;
      }

      oldParentFolderPaths.add(oldParentFolderPath);
    }

    // Folders first: each one takes everything inside it, so nothing below is reached twice.
    for (const unitFolder of unitFoldersToDelete) {
      abortSignal.throwIfAborted();
      recordOldParentFolderPath(unitFolder.path);
      await trashSafe(this.app, unitFolder);
    }

    for (const attachment of attachmentsToDelete) {
      abortSignal.throwIfAborted();
      recordOldParentFolderPath(attachment.path);
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

  private async findUnusedAttachments(note: TFile, abortSignal: AbortSignal): Promise<NoteScanResult> {
    const referencedAttachmentPaths = await this.collectReferencedAttachmentPaths(note, abortSignal);

    const attachmentFolderPath = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
      actionContext: ActionContext.Unknown,
      attachmentFileName: PLACEHOLDER_ATTACHMENT_FILE_NAME,
      notePath: note.path
    });
    abortSignal.throwIfAborted();

    const attachmentFolder = this.app.vault.getFolderByPath(attachmentFolderPath);
    if (!attachmentFolder) {
      return {
        referencedAttachmentPaths,
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

    const scanResult = await this.judgeCandidates({
      abortSignal,
      candidates,
      notePath: note.path,
      shouldShowProgressBar: false
    });

    return {
      referencedAttachmentPaths,
      unusedAttachments: scanResult.unusedAttachments,
      unusedUnitFolders: scanResult.unusedUnitFolders
    };
  }

  /**
   * Decides which of a set of attachment candidates are unused, and which of their unit folders are.
   *
   * Shared by both passes, which differ only in how they FOUND the candidates. The note-driven pass names
   * the note it scanned; the attachment-driven pass has no note and passes `null`, which simply makes the
   * "discount the scanning note's own backlink" filter below match nothing. That is the conservative
   * direction — a file with any backlink at all survives — so the two passes can never disagree about
   * keeping a file, only about reaching it.
   *
   * @param params - The candidates, the note that produced them, and how to report progress.
   * @returns What the candidates contribute to the sweep.
   */
  private async judgeCandidates(params: UnusedAttachmentsRemoverJudgeCandidatesParams): Promise<UnusedAttachmentsScanResult> {
    const abortSignal = params.abortSignal;
    const candidates = params.candidates;
    const notePath = params.notePath;

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
       * happens to contain the scanning note itself, and — for the attachment-driven pass, which has no
       * scanning note — any unit a live note lives in.
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

    const judgeCandidate = async (candidate: TFile): Promise<void> => {
      abortSignal.throwIfAborted();
      const backlinks = await getBacklinksForFileSafe({
        app: this.app,
        pathOrFile: candidate,
        timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
      });
      // An attachment is unused only when no OTHER note still references it. Notes matching the
      // Multiple-notes-check exclusion are ignored, mirroring the Collect/Move commands, so a shared
      // Attachment is never trashed. With no scanning note, `notePath` matches no backlink and every
      // Reference counts, which is the safe way to be wrong.
      const relevantBacklinks = backlinks.keys().filter((backlink) => backlink !== notePath && !this.pluginSettingsComponent.settings.isExcludedFromMultipleNotesCheck(backlink));
      if (relevantBacklinks.length === 0) {
        unusedAttachments.push(candidate);
      }
    };

    // Same rule as the note-driven pass applies to its own notice: `loop` holds its notice for a minimum
    // Two seconds, so putting one in front of a single candidate turns an instant answer into a slow one.
    if (params.shouldShowProgressBar && perFileCandidates.length > 1) {
      await loop({
        abortSignal,
        buildNoticeMessage: ({ item, iterationString }) => t(($) => $.deleteUnusedAttachments.orphanProgressBar.message, { attachmentFilePath: item.path, iterationString }),
        items: perFileCandidates,
        pluginNoticeComponent: this.pluginNoticeComponent,
        processItem: judgeCandidate,
        progressBarTitle: `${this.pluginName}: ${t(($) => $.deleteUnusedAttachments.orphanProgressBar.title)}`,
        shouldContinueOnError: true,
        shouldShowProgressBar: true
      });
      // `loop` returns quietly when the signal trips mid-run, so the abort has to be re-raised here or a
      // Cancelled scan would go on to show a confirmation dialog built from a partial answer.
      abortSignal.throwIfAborted();
    } else {
      for (const candidate of perFileCandidates) {
        await judgeCandidate(candidate);
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
