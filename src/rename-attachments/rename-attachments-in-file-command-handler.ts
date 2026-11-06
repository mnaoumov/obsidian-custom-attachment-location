import type { AbortSignalComponent } from '@mnaoumov/obsidian-lib/components/abort-signal-component';
import type { BulkOperationCommitComponent } from '@mnaoumov/obsidian-lib/components/bulk-operation-commit-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type {
  App,
  TAbstractFile,
  TFile
} from 'obsidian';

import { findAttachmentUnitFolderPath } from '@mnaoumov/obsidian-lib/attachment-unit-folder';
import { AbstractFileCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/abstract-file-command-handler';
import {
  isFile,
  isMarkdownFile
} from '@mnaoumov/obsidian-lib/file-system';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { extractReferenceFile } from '@mnaoumov/obsidian-lib/link';
import { loop } from '@mnaoumov/obsidian-lib/loop';
import {
  getBacklinksForFileSafe,
  getCacheSafe,
  getReferences
} from '@mnaoumov/obsidian-lib/metadata-cache';
import { addToQueueAndWait } from '@mnaoumov/obsidian-lib/queue';
import { renameSafe } from '@mnaoumov/obsidian-lib/vault';
import { abortSignalAny } from '@mnaoumov/typescript-lib/abort-controller';
import { dirname } from '@mnaoumov/typescript-lib/path';
import { isReferenceCache } from '@obsidian-typings/obsidian-public-latest/implementations';

import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { AttachmentPathManager } from '../attachment-location/attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';

import { buildBulkOperationSummary } from '../bulk-operations/bulk-operation-summary.ts';
import { findSidecarBase } from '../sidecars/sidecar-matcher.ts';

interface RenameAttachmentsInFileCommandHandlerConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
 * One attachment the note links, with the place of its first link in the note.
 */
interface RenameCandidate {
  readonly attachmentFile: TFile;
  readonly cursorLine: number;
}

/**
 * What one run did, for the closing notice.
 */
interface RenameRunResult {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Counted up while the run walks the note's attachments.
  renamedCount: number;
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Counted up while the run walks the note's attachments.
  skippedCount: number;
}

/**
 * `Rename attachments in current note`: gives each attachment of a note the name the rename template makes for it, in
 * the folder it already sits in, and lets the links follow.
 *
 * It is the in-place half of collecting. Collecting decides where an attachment BELONGS and moves it there; this
 * command never changes a folder, so an attachment kept in a shared folder on purpose stays there. With the template
 * left empty it uses the generated-name template, so an attachment that kept the name it was pasted or dropped with
 * gets the name a new one would get.
 *
 * Four kinds of attachment are left alone, each for a reason renaming cannot work around:
 *
 * - a path the rename/delete handler ignores, which this plugin never touches;
 * - a file inside an attachment unit folder, whose tree refers to it by its name;
 * - a sidecar companion, whose name is derived from its base and follows the base's rename on its own;
 * - an attachment another note links too, which a name made for THIS note would mislabel for the others. Notes the
 *   multiple-notes check excludes do not count.
 */
export class RenameAttachmentsInFileCommandHandler extends AbstractFileCommandHandler {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: RenameAttachmentsInFileCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.renameAttachmentsInFile),
      icon: 'text-cursor-input',
      id: 'rename-attachments-in-file',
      name: t(($) => $.commands.renameAttachmentsCurrentNote)
    });

    this.abortSignalComponent = params.abortSignalComponent;
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.bulkOperationCommitComponent = params.bulkOperationCommitComponent;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
   * Whether the command may run for one file: a Markdown note only.
   *
   * A canvas is left out on purpose. Its text-node embeds are not in the metadata cache, so a rename would leave them
   * pointing at the old name. This is the per-file predicate every surface reaches: the command palette, through
   * `canExecute`, and the file menu.
   *
   * @param abstractFile - The file or folder.
   * @returns Whether the command may run for it.
   */
  protected override canExecuteAbstractFile(abstractFile: TAbstractFile): boolean {
    return isFile(abstractFile) && isMarkdownFile(abstractFile);
  }

  protected override async executeAbstractFile(abstractFile: TAbstractFile): Promise<void> {
    if (!isFile(abstractFile)) {
      return;
    }

    const note = abstractFile;
    if (this.handedOverSettingsComponent.isPathIgnored(note.path)) {
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.notePathIsIgnored));
      console.warn(`Cannot rename attachments in the note as note path is ignored: ${note.path}.`);
      return;
    }

    // Wrapped from OUTSIDE the queue: the commit's settle step flushes the queue, so a wrap inside it would wait on itself.
    await this.bulkOperationCommitComponent.runBulkOperation({
      operation: () =>
        addToQueueAndWait({
          abortSignal: this.abortSignalComponent.abortSignal,
          operationFunction: (abortSignal) => this.renameAttachments(note, abortSignal),
          operationName: t(($) => $.commands.renameAttachmentsCurrentNote),
          timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
        }),
      summary: buildBulkOperationSummary('Rename attachments', [note])
    });
  }

  protected override shouldAddToAbstractFileMenu(): boolean {
    return true;
  }

  private async canRename(attachmentFile: TFile): Promise<boolean> {
    if (this.handedOverSettingsComponent.isPathIgnored(attachmentFile.path)) {
      console.warn(`Skipping renaming attachment ${attachmentFile.path} as its path is ignored.`);
      return false;
    }

    const unitFolderPath = findAttachmentUnitFolderPath({ app: this.app, attachmentPath: attachmentFile.path });
    if (unitFolderPath) {
      console.warn(`Skipping renaming attachment ${attachmentFile.path} as it belongs to the attachment unit folder ${unitFolderPath}.`);
      return false;
    }

    const folderPath = dirname(attachmentFile.path);
    const siblingNames = this.app.vault.getFiles().filter((file) => dirname(file.path) === folderPath).map((file) => file.name);
    if (findSidecarBase({ extensions: this.pluginSettingsComponent.settings.sidecarExtensions, name: attachmentFile.name, names: siblingNames })) {
      console.warn(`Skipping renaming attachment ${attachmentFile.path} as it is a sidecar named after its base.`);
      return false;
    }

    const backlinks = await getBacklinksForFileSafe({
      app: this.app,
      pathOrFile: attachmentFile,
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
    });
    const relevantBacklinks = backlinks.keys().filter((backlink) => !this.pluginSettingsComponent.settings.isExcludedFromMultipleNotesCheck(backlink));
    if (relevantBacklinks.length > 1) {
      console.warn(`Skipping renaming attachment ${attachmentFile.path} as it is referenced by multiple notes.\n${relevantBacklinks.map((backlink) => `- ${backlink}`).join('\n')}`);
      return false;
    }

    return true;
  }

  private async collectCandidates(note: TFile, result: RenameRunResult): Promise<RenameCandidate[]> {
    const cache = await getCacheSafe(this.app, note);
    if (!cache) {
      return [];
    }

    const candidates = new Map<string, RenameCandidate>();
    const examinedPaths = new Set<string>();
    for (const reference of getReferences({ cache })) {
      const attachmentFile = extractReferenceFile({
        app: this.app,
        reference,
        sourcePathOrFile: note
      });
      if (!attachmentFile || attachmentFile === note || examinedPaths.has(attachmentFile.path)) {
        continue;
      }
      examinedPaths.add(attachmentFile.path);

      if (this.pluginSettingsComponent.isNoteEx(attachmentFile)) {
        continue;
      }

      if (!await this.canRename(attachmentFile)) {
        result.skippedCount++;
        continue;
      }

      candidates.set(attachmentFile.path, {
        attachmentFile,
        cursorLine: isReferenceCache(reference) ? reference.position.start.line : 0
      });
    }

    return [...candidates.values()];
  }

  private async renameAttachments(note: TFile, abortSignal: AbortSignal): Promise<void> {
    const combinedAbortSignal = abortSignalAny(abortSignal, this.abortSignalComponent.abortSignal);
    const result: RenameRunResult = { renamedCount: 0, skippedCount: 0 };
    const candidates = await this.collectCandidates(note, result);
    combinedAbortSignal.throwIfAborted();

    // Snapshot the numbering before any rename, as collecting does: a rename rewrites the note's links.
    const sequenceNumberByAttachmentPath = await this.attachmentPathManager.getSequenceNumberMap(note.path);
    combinedAbortSignal.throwIfAborted();

    await loop({
      abortSignal: combinedAbortSignal,
      buildNoticeMessage: ({ item, iterationString }) => t(($) => $.renameAttachments.progressBar.message, { attachmentFilePath: item.attachmentFile.path, iterationString }),
      items: candidates,
      pluginNoticeComponent: this.pluginNoticeComponent,
      processItem: async ({ attachmentFile, cursorLine }) => {
        combinedAbortSignal.throwIfAborted();
        const newAttachmentPath = await this.attachmentPathManager.getRenamedAttachmentPath({
          attachmentFile,
          cursorLine,
          noteFilePath: note.path,
          sequenceNumber: sequenceNumberByAttachmentPath.get(attachmentFile.path) ?? 0
        });
        combinedAbortSignal.throwIfAborted();
        if (!newAttachmentPath) {
          return;
        }

        await renameSafe({
          app: this.app,
          newPath: newAttachmentPath,
          oldPathOrAbstractFile: attachmentFile
        });
        result.renamedCount++;
      },
      progressBarTitle: t(($) => $.renameAttachments.progressBar.title),
      shouldContinueOnError: true,
      shouldShowProgressBar: true
    });

    this.pluginNoticeComponent.showNotice(
      result.skippedCount > 0
        ? t(($) => $.renameAttachments.doneWithSkipped, { noteFilePath: note.path, renamedCount: result.renamedCount, skippedCount: result.skippedCount })
        : t(($) => $.renameAttachments.done, { noteFilePath: note.path, renamedCount: result.renamedCount })
    );
  }
}
