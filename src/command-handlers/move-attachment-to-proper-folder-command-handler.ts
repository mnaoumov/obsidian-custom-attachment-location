import type {
  App,
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

interface MoveAttachmentToProperFolderContext {
  mode?: MoveAttachmentToProperFolderUsedByMultipleNotesMode;
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

    if (
      !isMultipleNotesCheckSkippedByExtension && relevantBacklinkKeys.length > 1
      && !await shouldContinueWithMode(context.mode ?? this.pluginSettingsComponent.settings.moveAttachmentToProperFolderUsedByMultipleNotesMode)
    ) {
      return false;
    }

    for (const backlink of backlinksToCopy) {
      const backlinkFile = this.app.vault.getFileByPath(backlink);
      if (!backlinkFile) {
        continue;
      }

      const references = ensureNonNullable(backlinks.get(backlink));
      const link = references[0];
      if (!link) {
        continue;
      }

      const sequenceNumberByAttachmentPath = await this.attachmentPathManager.getSequenceNumberMap(backlink);
      const newAttachmentPath = await this.attachmentPathManager.getProperAttachmentPath({
        actionContext: ActionContext.MoveAttachmentToProperFolder,
        attachmentFile,
        noteFilePath: backlink,
        reference: link,
        sequenceNumber: sequenceNumberByAttachmentPath.get(attachmentFile.path) ?? 0
      });
      if (!newAttachmentPath) {
        console.warn(`Skipping moving attachment ${attachmentFile.path} to proper folder as it is already in the destination folder.`);
        continue;
      }

      const linkJsons = new Set(references.map((reference) => toJson(reference)));

      await copySafe({
        app: this.app,
        newPath: newAttachmentPath,
        oldPathOrFile: attachmentFile
      });
      await editLinks({
        app: this.app,
        linkConverter: (link2) => {
          const linkJson = toJson(link2);
          if (!linkJsons.has(linkJson)) {
            return;
          }

          return updateLink({
            app: this.app,
            link: link2,
            newSourcePathOrFile: backlinkFile,
            newTargetPathOrFile: newAttachmentPath,
            oldTargetPathOrFile: attachmentFile
          });
        },
        pathOrFile: backlinkFile,
        pluginNoticeComponent: this.pluginNoticeComponent,
        resourceLockComponent: this.resourceLockComponent
      });
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
}
