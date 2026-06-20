import type {
  Reference,
  TAbstractFile
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';
import type { MaybeReturn } from 'obsidian-dev-utils/type';

import {
  App,
  Notice,
  setIcon,
  TFile,
  Vault
} from 'obsidian';
import { abortSignalAny } from 'obsidian-dev-utils/abort-controller';
import { appendCodeBlock } from 'obsidian-dev-utils/html-element';
import {
  isCanvasFile,
  isFile,
  isFolder,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  editLinks,
  extractLinkFile,
  updateLink
} from 'obsidian-dev-utils/obsidian/link';
import { loop } from 'obsidian-dev-utils/obsidian/loop';
import {
  getAllLinks,
  getBacklinksForFileSafe,
  getCacheSafe
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { addToQueue } from 'obsidian-dev-utils/obsidian/queue';
import {
  copySafe,
  renameSafe
} from 'obsidian-dev-utils/obsidian/vault';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { getCanvasLinks } from './canvas-links.ts';
import { selectMode } from './modals/collect-attachment-used-by-multiple-notes-modal.ts';
import { CollectAttachmentUsedByMultipleNotesMode } from './plugin-settings.ts';
import { ActionContext } from './token-evaluator-context.ts';

interface AttachmentCollectorCollectAttachmentsParams {
  readonly abortSignal: AbortSignal;
  readonly ctx: CollectAttachmentContext;
  readonly note: TFile;
}

interface AttachmentCollectorConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly consoleDebugComponent: ConsoleDebugComponent;
  readonly pluginName: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

interface AttachmentCollectorPrepareAttachmentToMoveParams {
  readonly newNotePath: string;
  readonly oldAttachmentPaths: Set<string>;
  readonly oldNotePath: string;
  readonly reference: Reference;
}

interface AttachmentMoveResult {
  readonly newAttachmentPath: null | string;
  readonly oldAttachmentPath: string;
}

interface CollectAttachmentContext {
  collectAttachmentUsedByMultipleNotesMode?: CollectAttachmentUsedByMultipleNotesMode;
  isAborted?: boolean;
}

export class AttachmentCollector {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly consoleDebugComponent: ConsoleDebugComponent;
  private readonly pluginName: string;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: AttachmentCollectorConstructorParams) {
    this.app = params.app;
    this.pluginName = params.pluginName;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.abortSignalComponent = params.abortSignalComponent;
    this.consoleDebugComponent = params.consoleDebugComponent;
    this.attachmentPathManager = params.attachmentPathManager;
  }

  public collectAttachmentsEntireVault(): void {
    addToQueue({
      abortSignal: this.abortSignalComponent.abortSignal,
      app: this.app,
      operationFn: (abortSignal) =>
        this.collectAttachmentsInAbstractFilesImpl(
          [this.app.vault.getRoot()],
          abortSignal
        ),
      operationName: t(($) => $.commands.collectAttachmentsEntireVault),
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
    });
  }

  public collectAttachmentsInAbstractFiles(abstractFiles: TAbstractFile[]): void {
    addToQueue({
      abortSignal: this.abortSignalComponent.abortSignal,
      app: this.app,
      operationFn: (abortSignal) => this.collectAttachmentsInAbstractFilesImpl(abstractFiles, abortSignal),
      operationName: t(($) => $.menuItems.collectAttachmentsInFile),
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
    });
  }

  private async collectAttachments(params: AttachmentCollectorCollectAttachmentsParams): Promise<void> {
    const app = this.app;
    const pluginSettingsComponent = this.pluginSettingsComponent;

    params.abortSignal.throwIfAborted();
    if (params.ctx.isAborted) {
      return;
    }

    const notice = new Notice(t(($) => $.notice.collectingAttachments, { noteFilePath: params.note.path }), 0);

    try {
      const isCanvas = isCanvasFile(app, params.note);

      const oldAttachmentPaths = new Set<string>();

      const cache = await getCacheSafe(app, params.note);
      params.abortSignal.throwIfAborted();

      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Could be changed in await call.
      if (params.ctx.isAborted) {
        return;
      }

      if (!cache) {
        return;
      }

      const links = isCanvas ? await getCanvasLinks(app, params.note) : getAllLinks(cache);
      params.abortSignal.throwIfAborted();

      for (const link of links) {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Could be changed in await call.
        if (params.ctx.isAborted) {
          return;
        }

        let attachmentMoveResult = await this.prepareAttachmentToMove({
          newNotePath: params.note.path,
          oldAttachmentPaths,
          oldNotePath: params.note.path,
          reference: link
        });
        params.abortSignal.throwIfAborted();
        if (!attachmentMoveResult) {
          continue;
        }

        if (this.pluginSettingsComponent.settings.isExcludedFromAttachmentCollecting(attachmentMoveResult.oldAttachmentPath)) {
          console.warn(`Skipping collecting attachment ${attachmentMoveResult.oldAttachmentPath} as it is excluded from attachment collecting.`);
          continue;
        }

        const backlinks = await getBacklinksForFileSafe(this.app, attachmentMoveResult.oldAttachmentPath, {
          timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
        });
        params.abortSignal.throwIfAborted();
        if (backlinks.keys().length > 1) {
          const backlinksSorted = backlinks.keys().sort((a, b) => a.localeCompare(b));
          const backlinksStr = backlinksSorted.map((backlink) => `- ${backlink}`).join('\n');

          async function applyCollectAttachmentUsedByMultipleNotesMode(
            collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode
          ): Promise<boolean> {
            params.abortSignal.throwIfAborted();
            let result = ensureNonNullable(attachmentMoveResult);

            switch (collectAttachmentUsedByMultipleNotesMode) {
              case CollectAttachmentUsedByMultipleNotesMode.Cancel:
                console.error(
                  `Cancelling collecting attachments, as attachment ${result.oldAttachmentPath} is referenced by multiple notes.\n${backlinksStr}`
                );
                if (pluginSettingsComponent.settings.collectAttachmentUsedByMultipleNotesMode === CollectAttachmentUsedByMultipleNotesMode.Cancel) {
                  await selectMode(app, result.oldAttachmentPath, backlinksSorted, true);
                }
                // eslint-disable-next-line require-atomic-updates -- Cannot avoid.
                params.ctx.isAborted = true;
                return false;
              case CollectAttachmentUsedByMultipleNotesMode.Copy:
                if (!result.newAttachmentPath) {
                  console.warn(`Skipping collecting attachment ${result.oldAttachmentPath} as it is already in the destination folder.`);
                  return false;
                }
                // eslint-disable-next-line require-atomic-updates -- Ignore possible race condition.
                result = {
                  ...result,
                  newAttachmentPath: await copySafe(app, result.oldAttachmentPath, result.newAttachmentPath)
                };
                await editLinks(app, params.note, (link2): MaybeReturn<string> => {
                  const linkFile = extractLinkFile(app, link2, params.note);
                  if (linkFile?.path !== result.oldAttachmentPath) {
                    return;
                  }
                  return updateLink({
                    app,
                    link: link2,
                    newSourcePathOrFile: params.note,
                    newTargetPathOrFile: ensureNonNullable(result.newAttachmentPath),
                    oldSourcePathOrFile: params.note,
                    oldTargetPathOrFile: result.oldAttachmentPath
                  });
                });
                break;
              case CollectAttachmentUsedByMultipleNotesMode.Move:
                if (!result.newAttachmentPath) {
                  console.warn(`Skipping collecting attachment ${result.oldAttachmentPath} as it is already in the destination folder.`);
                  return false;
                }
                await registerMoveAttachment();
                params.abortSignal.throwIfAborted();
                break;
              case CollectAttachmentUsedByMultipleNotesMode.Prompt: {
                const { mode, shouldUseSameActionForOtherProblematicAttachments } = await selectMode(
                  app,
                  result.oldAttachmentPath,
                  backlinksSorted
                );
                if (shouldUseSameActionForOtherProblematicAttachments) {
                  // eslint-disable-next-line require-atomic-updates -- Cannot avoid.
                  params.ctx.collectAttachmentUsedByMultipleNotesMode = mode;
                }
                return applyCollectAttachmentUsedByMultipleNotesMode(mode);
              }
              case CollectAttachmentUsedByMultipleNotesMode.Skip:
                console.warn(
                  `Skipping collecting attachment ${result.oldAttachmentPath} as it is referenced by multiple notes.\n${backlinksStr}`
                );
                return false;
              default:
                throw new Error(
                  `Unknown collect attachment used by multiple notes mode: ${pluginSettingsComponent.settings.collectAttachmentUsedByMultipleNotesMode}`
                );
            }

            return true;
          }

          if (
            !await applyCollectAttachmentUsedByMultipleNotesMode(
              params.ctx.collectAttachmentUsedByMultipleNotesMode ?? pluginSettingsComponent.settings.collectAttachmentUsedByMultipleNotesMode
            )
          ) {
            params.abortSignal.throwIfAborted();
            continue;
          }
        } else {
          params.abortSignal.throwIfAborted();
          await registerMoveAttachment();
          params.abortSignal.throwIfAborted();
        }

        async function registerMoveAttachment(): Promise<void> {
          params.abortSignal.throwIfAborted();
          if (!attachmentMoveResult?.newAttachmentPath) {
            return;
          }

          // eslint-disable-next-line require-atomic-updates -- Ignore possible race condition.
          attachmentMoveResult = {
            ...attachmentMoveResult,
            newAttachmentPath: await renameSafe(app, attachmentMoveResult.oldAttachmentPath, attachmentMoveResult.newAttachmentPath)
          };
        }
      }
    } finally {
      notice.hide();
    }
  }

  private async collectAttachmentsInAbstractFilesImpl(abstractFiles: TAbstractFile[], abortSignal: AbortSignal): Promise<void> {
    abortSignal.throwIfAborted();
    const singleFile: null | TFile = abstractFiles.length === 1 && isFile(abstractFiles[0]) ? abstractFiles[0] : null;

    if (singleFile && this.pluginSettingsComponent.settings.isPathIgnored(singleFile.path)) {
      new Notice(t(($) => $.notice.notePathIsIgnored));
      console.warn(`Cannot collect attachments in the note as note path is ignored: ${singleFile.path}.`);
      return;
    }

    const canCollectAttachments = !!singleFile || (await confirm({
      app: this.app,
      cancelButtonText: t(($) => $.obsidianDevUtils.buttons.cancel),
      message: createFragment((f) => {
        f.appendText(t(($) => $.attachmentCollector.confirm.part1));
        f.createEl('br');
        f.createEl('ul', {}, (ul) => {
          for (const abstractFile of abstractFiles) {
            ul.createEl('li', {}, (li) => {
              appendCodeBlock(li, abstractFile.path);
            });
          }
        });
        f.createEl('br');
        f.appendText(t(($) => $.attachmentCollector.confirm.part2));
      }),
      okButtonText: t(($) => $.obsidianDevUtils.buttons.ok),
      title: createFragment((f) => {
        setIcon(f.createSpan(), 'lucide-alert-triangle');
        f.appendText(' ');
        f.appendText(t(($) => $.menuItems.collectAttachmentsInFiles));
      })
    }));

    if (!canCollectAttachments) {
      abortSignal.throwIfAborted();
      return;
    }
    this.consoleDebugComponent.consoleDebug(`Collect attachments in files:\n${abstractFiles.map((abstractFile) => abstractFile.path).join('\n')}`);
    const noteFilesSet = new Set<TFile>();

    for (const abstractFile of abstractFiles) {
      if (isFile(abstractFile) && isNote(this.app, abstractFile)) {
        noteFilesSet.add(abstractFile);
      }

      if (isFolder(abstractFile)) {
        Vault.recurseChildren(abstractFile, (child) => {
          if (isFile(child) && isNote(this.app, child)) {
            noteFilesSet.add(child);
          }
        });
      }
    }

    const noteFiles = Array.from(noteFilesSet);
    noteFiles.sort((a, b) => a.path.localeCompare(b.path));

    const ctx: CollectAttachmentContext = {};
    const abortController = new AbortController();

    const combinedAbortSignal = abortSignalAny(abortController.signal, this.abortSignalComponent.abortSignal);

    await loop({
      abortSignal: combinedAbortSignal,
      buildNoticeMessage: (noteFile, iterationStr) => t(($) => $.attachmentCollector.progressBar.message, { iterationStr, noteFilePath: noteFile.path }),
      items: noteFiles,
      processItem: async (noteFile) => {
        combinedAbortSignal.throwIfAborted();
        if (this.pluginSettingsComponent.settings.isPathIgnored(noteFile.path)) {
          console.warn(`Cannot collect attachments in the note as note path is ignored: ${noteFile.path}.`);
          return;
        }
        await this.collectAttachments({
          abortSignal: combinedAbortSignal,
          ctx,
          note: noteFile
        });
        combinedAbortSignal.throwIfAborted();
        if (ctx.isAborted) {
          abortController.abort();
        }
      },
      progressBarTitle: `${this.pluginName}: ${t(($) => $.attachmentCollector.progressBar.title)}`,
      shouldContinueOnError: true,
      shouldShowProgressBar: true
    });
  }

  private async prepareAttachmentToMove(params: AttachmentCollectorPrepareAttachmentToMoveParams): Promise<AttachmentMoveResult | null> {
    const oldAttachmentFile = extractLinkFile(this.app, params.reference, params.oldNotePath, true);

    if (!oldAttachmentFile) {
      return null;
    }

    if (this.pluginSettingsComponent.isNoteEx(oldAttachmentFile)) {
      return null;
    }

    if (params.oldAttachmentPaths.has(oldAttachmentFile.path)) {
      return null;
    }

    params.oldAttachmentPaths.add(oldAttachmentFile.path);

    if (oldAttachmentFile.deleted) {
      console.warn(`Skipping collecting attachment ${params.reference.link} as it could not be resolved.`);
      return null;
    }

    const newAttachmentPath = await this.attachmentPathManager.getProperAttachmentPath({
      actionContext: ActionContext.CollectAttachments,
      attachmentFile: oldAttachmentFile,
      noteFilePath: params.newNotePath,
      reference: params.reference
    });

    return {
      newAttachmentPath,
      oldAttachmentPath: oldAttachmentFile.path
    };
  }
}
