import type {
  App,
  TAbstractFile,
  TFile
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';

import {
  setIcon,
  Vault
} from 'obsidian';
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
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { ActionContext } from './token-evaluator-context.ts';

// The note's attachment folder path template rarely depends on the attachment file name (the default
// `./assets/${noteFileName}` does not), so a placeholder name is enough to resolve the folder to scan.
const PLACEHOLDER_ATTACHMENT_FILE_NAME = 'unused-attachment';

interface UnusedAttachmentsRemoverConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class UnusedAttachmentsRemover {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: UnusedAttachmentsRemoverConstructorParams) {
    this.abortSignalComponent = params.abortSignalComponent;
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public deleteUnusedAttachmentsInAbstractFiles(abstractFiles: TAbstractFile[]): void {
    addToQueue({
      abortSignal: this.abortSignalComponent.abortSignal,
      operationFn: (abortSignal) => this.deleteUnusedAttachmentsInAbstractFilesImpl(abstractFiles, abortSignal),
      operationName: t(($) => $.menuItems.deleteUnusedAttachmentsInFile),
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
    });
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

    const noteFiles = Array.from(noteFilesSet).sort((a, b) => a.path.localeCompare(b.path));

    // Compute the full set of attachments to trash BEFORE deleting anything, so the confirmation
    // Modal lists exactly what will be removed.
    const unusedAttachments = new Set<TFile>();
    for (const noteFile of noteFiles) {
      abortSignal.throwIfAborted();
      if (this.pluginSettingsComponent.settings.isPathIgnored(noteFile.path)) {
        console.warn(`Cannot delete unused attachments as note path is ignored: ${noteFile.path}.`);
        continue;
      }

      for (const attachment of await this.findUnusedAttachments(noteFile, abortSignal)) {
        unusedAttachments.add(attachment);
      }
    }

    if (unusedAttachments.size === 0) {
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.noUnusedAttachments));
      return;
    }

    const attachmentsToDelete = Array.from(unusedAttachments).sort((a, b) => a.path.localeCompare(b.path));

    const isConfirmed = await confirm({
      app: this.app,
      cancelButtonText: t(($) => $.obsidianDevUtils.buttons.cancel),
      message: createFragment((f) => {
        f.appendText(t(($) => $.deleteUnusedAttachments.confirm.part1));
        f.createEl('br');
        f.createEl('ul', {}, (ul) => {
          for (const attachment of attachmentsToDelete) {
            ul.createEl('li', {}, (li) => {
              appendCodeBlock(li, attachment.path);
            });
          }
        });
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
    for (const attachment of attachmentsToDelete) {
      abortSignal.throwIfAborted();
      oldParentFolderPaths.add(dirname(attachment.path));
      await trashSafe(this.app, attachment);
    }

    await cleanupEmptyFolders({
      app: this.app,
      emptyFolderBehavior: this.pluginSettingsComponent.settings.emptyFolderBehavior,
      folderPaths: Array.from(oldParentFolderPaths)
    });
  }

  private async findUnusedAttachments(note: TFile, abortSignal: AbortSignal): Promise<TFile[]> {
    const cache = await getCacheSafe(this.app, note);
    abortSignal.throwIfAborted();
    if (!cache) {
      return [];
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
      return [];
    }

    const candidates: TFile[] = [];
    Vault.recurseChildren(attachmentFolder, (child) => {
      if (isFile(child) && !this.pluginSettingsComponent.isNoteEx(child) && !referencedAttachmentPaths.has(child.path)) {
        candidates.push(child);
      }
    });

    const unusedAttachments: TFile[] = [];
    for (const candidate of candidates) {
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

    return unusedAttachments;
  }
}
