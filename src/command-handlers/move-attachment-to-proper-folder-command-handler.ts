import type {
  App,
  Reference,
  TAbstractFile,
  TFile
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import type { ResourceLockComponent } from 'obsidian-dev-utils/obsidian/resource-lock';
import type { Promisable } from 'type-fest';

import { Vault } from 'obsidian';
import { abortSignalAny } from 'obsidian-dev-utils/abort-controller';
import { toJson } from 'obsidian-dev-utils/object-utils';
import { AbstractFileCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/abstract-file-command-handler';
import {
  isFile,
  isFolder
} from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  editLinks,
  updateLink
} from 'obsidian-dev-utils/obsidian/link';
import { loop } from 'obsidian-dev-utils/obsidian/loop';
import { getBacklinksForFileSafe } from 'obsidian-dev-utils/obsidian/metadata-cache';
import { copySafe } from 'obsidian-dev-utils/obsidian/vault';
import { deleteIfNotUsed } from 'obsidian-dev-utils/obsidian/vault-delete';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';
import type { HandedOverSettingsComponent } from '../handed-over-settings-component.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { selectMode } from '../modals/move-attachment-to-proper-folder-used-by-multiple-notes-modal.ts';
import { MoveAttachmentToProperFolderUsedByMultipleNotesMode } from '../plugin-settings.ts';
import { ActionContext } from '../token-evaluator-context.ts';

interface MoveAttachmentToProperFolderCommandHandlerConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly resourceLockComponent: null | ResourceLockComponent;
}

interface MoveAttachmentToProperFolderCommandHandlerRelinkNoteParams {
  readonly attachmentFile: TFile;
  readonly newAttachmentPath: string;
  readonly notePath: string;
  readonly references: readonly Reference[];
}

interface MoveAttachmentToProperFolderContext {
  mode?: MoveAttachmentToProperFolderUsedByMultipleNotesMode;
}

/**
 * One copy of the attachment: the note whose attachment folder decides where it goes, and the notes whose links are
 * pointed at that copy.
 */
interface MovePlanEntry {
  readonly destinationNotePath: string;
  readonly relinkedNotePaths: readonly string[];
}

export class MoveAttachmentToProperFolderCommandHandler extends AbstractFileCommandHandler {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly resourceLockComponent: null | ResourceLockComponent;

  public constructor(params: MoveAttachmentToProperFolderCommandHandlerConstructorParams) {
    super({
      icon: 'move',
      id: 'move-attachment-to-proper-folder',
      name: t(($) => $.commands.moveAttachmentToProperFolder)
    });

    this.abortSignalComponent = params.abortSignalComponent;
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.resourceLockComponent = params.resourceLockComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
   * Whether the command may run for one file or folder.
   *
   * This is the PER-FILE predicate, and it is the one all three surfaces reach: the base routes the
   * command palette (`canExecute`), the single-file menu and — by composing this over every entry — the
   * multi-select menu through it. A `canExecuteAbstractFiles` override was doing the work for the last of
   * those alone, so the palette and the file menu offered the command on a note, whose walk in
   * `executeAbstractFiles` then filtered it out and did nothing. It also opened with `super.canExecute()`,
   * which tests the ACTIVE file: a condition that has nothing to do with a menu built from the files the
   * user clicked.
   *
   * @param abstractFile - The file or folder.
   * @returns Whether the command may run for it. A folder always may — the walk inside it filters.
   */
  protected override canExecuteAbstractFile(abstractFile: TAbstractFile): boolean {
    return !isFile(abstractFile) || !this.pluginSettingsComponent.isNoteEx(abstractFile);
  }

  protected override executeAbstractFile(abstractFile: TAbstractFile): Promisable<void> {
    return this.executeAbstractFiles([abstractFile]);
  }

  protected override async executeAbstractFiles(abstractFiles: TAbstractFile[]): Promise<void> {
    const attachmentFilesSet = new Set<TFile>();

    for (const abstractFile of abstractFiles) {
      if (isFile(abstractFile) && !this.pluginSettingsComponent.isNoteEx(abstractFile)) {
        attachmentFilesSet.add(abstractFile);
      }

      if (isFolder(abstractFile)) {
        Vault.recurseChildren(abstractFile, (child) => {
          if (isFile(child) && !this.pluginSettingsComponent.isNoteEx(child)) {
            attachmentFilesSet.add(child);
          }
        });
      }
    }

    const attachmentFiles = [...attachmentFilesSet];
    attachmentFiles.sort((a, b) => a.path.localeCompare(b.path));

    const abortController = new AbortController();
    const combinedAbortSignal = abortSignalAny(abortController.signal, this.abortSignalComponent.abortSignal);
    const context: MoveAttachmentToProperFolderContext = {};

    await loop({
      abortSignal: combinedAbortSignal,
      buildNoticeMessage: ({ item, iterationString }) => t(($) => $.moveAttachmentToProperFolder.progressBar.message, { attachmentFilePath: item.path, iterationString }),
      items: attachmentFiles,
      pluginNoticeComponent: this.pluginNoticeComponent,
      processItem: async (attachmentFile) => {
        combinedAbortSignal.throwIfAborted();
        if (this.handedOverSettingsComponent.isPathIgnored(attachmentFile.path)) {
          console.warn(`Cannot move attachment to proper folder as attachment path is ignored: ${attachmentFile.path}.`);
          return;
        }
        if (!await this.moveAttachmentToProperFolder(attachmentFile, context)) {
          return;
        }
        combinedAbortSignal.throwIfAborted();
      },
      progressBarTitle: `${this.pluginName}: ${t(($) => $.moveAttachmentToProperFolder.progressBar.title)}`,
      shouldContinueOnError: true,
      shouldShowProgressBar: true
    });
  }

  protected override shouldAddToAbstractFileMenu(): boolean {
    return true;
  }

  protected override shouldAddToAbstractFilesMenu(): boolean {
    return true;
  }

  private async moveAttachmentToProperFolder(attachmentFile: TFile, context: MoveAttachmentToProperFolderContext): Promise<boolean> {
    const app = this.app;
    const pluginSettingsComponent = this.pluginSettingsComponent;
    let backlinks = await getBacklinksForFileSafe({
      app: this.app,
      pathOrFile: attachmentFile
    });
    if (backlinks.keys().length === 0) {
      this.pluginNoticeComponent.showNotice(t(($) => $.moveAttachmentToProperFolder.unusedAttachment, { attachmentPath: attachmentFile.path }));
      return true;
    }

    let backlinksToCopy: string[] = [];

    // Notes matching the configured patterns are ignored when deciding whether the attachment is used by multiple notes.
    const relevantBacklinkKeys = [...backlinks.keys()].filter((backlink) => !this.pluginSettingsComponent.settings.isExcludedFromMultipleNotesCheck(backlink));

    // An attachment whose file type is declared deliberately shared never asks the question at all (issue #80).
    // Same rule, and same reason, as the Collect attachments branch in `attachment-collector.ts`.
    const isMultipleNotesCheckSkippedByExtension = this.pluginSettingsComponent.settings.isExtensionExcludedFromMultipleNotesCheck(attachmentFile.path);

    let movePlan: MovePlanEntry[];
    if (!isMultipleNotesCheckSkippedByExtension && relevantBacklinkKeys.length > 1) {
      if (!await shouldContinueWithMode(context.mode ?? this.pluginSettingsComponent.settings.moveAttachmentToProperFolderUsedByMultipleNotesMode)) {
        return false;
      }
      movePlan = backlinksToCopy.map((backlink) => ({ destinationNotePath: backlink, relinkedNotePaths: [backlink] }));
    } else {
      /*
       * Not a multiple-notes case, so the mode is never consulted and no modal is raised: this is a plain move. One note
       * decides the destination, and every note linking to the attachment follows it there, so the original ends up
       * unused and is deleted below. Before this branch existed nothing filled the plan here, and the command did nothing
       * at all for an attachment used by a single note - the common case.
       */
      const ownerCandidates = relevantBacklinkKeys.length > 0 ? relevantBacklinkKeys : backlinks.keys();
      const destinationNotePath = ensureNonNullable([...ownerCandidates].sort((a, b) => a.localeCompare(b))[0]);
      movePlan = [{ destinationNotePath, relinkedNotePaths: backlinks.keys() }];
    }

    for (const { destinationNotePath, relinkedNotePaths } of movePlan) {
      if (!this.app.vault.getFileByPath(destinationNotePath)) {
        continue;
      }

      const reference = backlinks.get(destinationNotePath)?.[0];
      if (!reference) {
        continue;
      }

      const sequenceNumberByAttachmentPath = await this.attachmentPathManager.getSequenceNumberMap(destinationNotePath);
      const newAttachmentPath = await this.attachmentPathManager.getProperAttachmentPath({
        actionContext: ActionContext.MoveAttachmentToProperFolder,
        attachmentFile,
        noteFilePath: destinationNotePath,
        reference,
        sequenceNumber: sequenceNumberByAttachmentPath.get(attachmentFile.path) ?? 0
      });
      if (!newAttachmentPath) {
        console.warn(`Skipping moving attachment ${attachmentFile.path} to proper folder as it is already in the destination folder.`);
        continue;
      }

      await copySafe({
        app: this.app,
        newPath: newAttachmentPath,
        oldPathOrFile: attachmentFile
      });

      for (const relinkedNotePath of relinkedNotePaths) {
        await this.relinkNote({
          attachmentFile,
          newAttachmentPath,
          notePath: relinkedNotePath,
          references: backlinks.get(relinkedNotePath) ?? []
        });
      }
    }

    backlinks = await getBacklinksForFileSafe({
      app: this.app,
      pathOrFile: attachmentFile
    });

    if (backlinks.keys().length === 0) {
      await deleteIfNotUsed({
        app: this.app,
        pathOrFile: attachmentFile
      });
    }

    return true;

    async function shouldContinueWithMode(mode: MoveAttachmentToProperFolderUsedByMultipleNotesMode): Promise<boolean> {
      switch (mode) {
        case MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel: {
          if (
            pluginSettingsComponent.settings.moveAttachmentToProperFolderUsedByMultipleNotesMode
              === MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel
          ) {
            await selectMode({ app, attachmentPath: attachmentFile.path, backlinks: relevantBacklinkKeys, isCancelMode: true });
          }
          return false;
        }
        case MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll: {
          backlinksToCopy = relevantBacklinkKeys;
          return true;
        }
        case MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt: {
          const { backlinksToCopy: backlinksToCopy2, mode: mode2, shouldUseSameActionForOtherProblematicAttachments } = await selectMode({
            app,
            attachmentPath: attachmentFile.path,
            backlinks: relevantBacklinkKeys
          });
          if (shouldUseSameActionForOtherProblematicAttachments) {
            context.mode = mode2;
          }

          if (mode2 === MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt) {
            backlinksToCopy = backlinksToCopy2;
            return true;
          }

          // eslint-disable-next-line unicorn/no-useless-recursion -- A single re-dispatch after the user picks a mode in the modal; a loop would obscure the switch.
          return shouldContinueWithMode(mode2);
        }
        case MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip: {
          backlinksToCopy = [];
          return true;
        }
        default: {
          return false;
        }
      }
    }
  }

  private async relinkNote(params: MoveAttachmentToProperFolderCommandHandlerRelinkNoteParams): Promise<void> {
    const noteFile = this.app.vault.getFileByPath(params.notePath);
    if (!noteFile) {
      return;
    }

    const linkJsons = new Set(params.references.map((reference) => toJson(reference)));

    await editLinks({
      app: this.app,
      linkConverter: (link) => {
        const linkJson = toJson(link);
        return linkJsons.has(linkJson)
          ? updateLink({
            app: this.app,
            link,
            newSourcePathOrFile: noteFile,
            newTargetPathOrFile: params.newAttachmentPath,
            oldTargetPathOrFile: params.attachmentFile
          })
          : undefined;
      },
      pathOrFile: noteFile,
      pluginNoticeComponent: this.pluginNoticeComponent,
      resourceLockComponent: this.resourceLockComponent
    });
  }
}
