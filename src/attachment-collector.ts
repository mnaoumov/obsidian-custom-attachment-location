import type {
  Reference,
  ReferenceCache,
  TAbstractFile
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';
import type { PathOrAbstractFile } from 'obsidian-dev-utils/obsidian/file-system';
import type { MaybeReturn } from 'obsidian-dev-utils/type';
import type { CanvasData } from 'obsidian/canvas.d.ts';

import { isReferenceCache } from '@obsidian-typings/obsidian-public-latest/implementations';
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
  getPath,
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
import {
  join,
  makeFileName
} from 'obsidian-dev-utils/path';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { Plugin } from './plugin.ts';

import {
  getAttachmentFolderFullPathForPath,
  getGeneratedAttachmentFileBaseName
} from './attachment-path.ts';
import { selectMode } from './modals/collect-attachment-used-by-multiple-notes-modal.ts';
import { CollectAttachmentUsedByMultipleNotesMode } from './plugin-settings.ts';
import { Substitutions } from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';

export interface GetProperAttachmentPathParams {
  readonly actionContext: ActionContext;
  readonly attachmentFile: TFile;
  readonly noteFilePath: string;
  readonly plugin: Plugin;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly reference: Reference;
}

interface AttachmentMoveResult {
  newAttachmentPath: null | string;
  oldAttachmentPath: string;
}

interface CollectAttachmentContext {
  collectAttachmentUsedByMultipleNotesMode?: CollectAttachmentUsedByMultipleNotesMode;
  isAborted?: boolean;
}

export async function collectAttachments(
  plugin: Plugin,
  note: TFile,
  ctx: CollectAttachmentContext,
  abortSignal: AbortSignal,
  pluginSettingsComponent: PluginSettingsComponent
): Promise<void> {
  abortSignal.throwIfAborted();
  const app = plugin.app;

  if (ctx.isAborted) {
    return;
  }

  const notice = new Notice(t(($) => $.notice.collectingAttachments, { noteFilePath: note.path }), 0);

  try {
    const isCanvas = isCanvasFile(app, note);

    const oldAttachmentPaths = new Set<string>();

    const cache = await getCacheSafe(app, note);
    abortSignal.throwIfAborted();

    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Could be changed in await call.
    if (ctx.isAborted) {
      return;
    }

    if (!cache) {
      return;
    }

    const links = isCanvas ? await getCanvasLinks(app, note) : getAllLinks(cache);
    abortSignal.throwIfAborted();

    for (const link of links) {
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Could be changed in await call.
      if (ctx.isAborted) {
        return;
      }

      const attachmentMoveResult = await prepareAttachmentToMove(plugin, link, note.path, note.path, oldAttachmentPaths, pluginSettingsComponent);
      abortSignal.throwIfAborted();
      if (!attachmentMoveResult) {
        continue;
      }

      if (pluginSettingsComponent.settings.isExcludedFromAttachmentCollecting(attachmentMoveResult.oldAttachmentPath)) {
        console.warn(`Skipping collecting attachment ${attachmentMoveResult.oldAttachmentPath} as it is excluded from attachment collecting.`);
        continue;
      }

      const backlinks = await getBacklinksForFileSafe(app, attachmentMoveResult.oldAttachmentPath, {
        timeoutInMilliseconds: pluginSettingsComponent.settings.getTimeoutInMilliseconds()
      });
      abortSignal.throwIfAborted();
      if (backlinks.keys().length > 1) {
        const backlinksSorted = backlinks.keys().sort((a, b) => a.localeCompare(b));
        const backlinksStr = backlinksSorted.map((backlink) => `- ${backlink}`).join('\n');

        async function applyCollectAttachmentUsedByMultipleNotesMode(
          collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode
        ): Promise<boolean> {
          abortSignal.throwIfAborted();
          const result = ensureNonNullable(attachmentMoveResult);

          switch (collectAttachmentUsedByMultipleNotesMode) {
            case CollectAttachmentUsedByMultipleNotesMode.Cancel:
              console.error(
                `Cancelling collecting attachments, as attachment ${result.oldAttachmentPath} is referenced by multiple notes.\n${backlinksStr}`
              );
              if (pluginSettingsComponent.settings.collectAttachmentUsedByMultipleNotesMode === CollectAttachmentUsedByMultipleNotesMode.Cancel) {
                await selectMode(app, result.oldAttachmentPath, backlinksSorted, true);
              }
              ctx.isAborted = true;
              return false;
            case CollectAttachmentUsedByMultipleNotesMode.Copy:
              if (!result.newAttachmentPath) {
                console.warn(`Skipping collecting attachment ${result.oldAttachmentPath} as it is already in the destination folder.`);
                return false;
              }
              // eslint-disable-next-line require-atomic-updates -- Ignore possible race condition.
              result.newAttachmentPath = await copySafe(app, result.oldAttachmentPath, result.newAttachmentPath);
              await editLinks(app, note, (link2): MaybeReturn<string> => {
                const linkFile = extractLinkFile(app, link2, note);
                if (linkFile?.path !== result.oldAttachmentPath) {
                  return;
                }
                return updateLink({
                  app,
                  link: link2,
                  newSourcePathOrFile: note,
                  newTargetPathOrFile: ensureNonNullable(result.newAttachmentPath),
                  oldSourcePathOrFile: note,
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
              abortSignal.throwIfAborted();
              break;
            case CollectAttachmentUsedByMultipleNotesMode.Prompt: {
              const { mode, shouldUseSameActionForOtherProblematicAttachments } = await selectMode(
                app,
                result.oldAttachmentPath,
                backlinksSorted
              );
              if (shouldUseSameActionForOtherProblematicAttachments) {
                ctx.collectAttachmentUsedByMultipleNotesMode = mode;
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
            ctx.collectAttachmentUsedByMultipleNotesMode ?? pluginSettingsComponent.settings.collectAttachmentUsedByMultipleNotesMode
          )
        ) {
          abortSignal.throwIfAborted();
          continue;
        }
      } else {
        abortSignal.throwIfAborted();
        await registerMoveAttachment();
        abortSignal.throwIfAborted();
      }

      async function registerMoveAttachment(): Promise<void> {
        abortSignal.throwIfAborted();
        if (!attachmentMoveResult?.newAttachmentPath) {
          return;
        }

        // eslint-disable-next-line require-atomic-updates -- Ignore possible race condition.
        attachmentMoveResult.newAttachmentPath = await renameSafe(app, attachmentMoveResult.oldAttachmentPath, attachmentMoveResult.newAttachmentPath);
      }
    }
  } finally {
    notice.hide();
  }
}

export function collectAttachmentsEntireVault(
  plugin: Plugin,
  abortSignalComponent: AbortSignalComponent,
  pluginSettingsComponent: PluginSettingsComponent,
  consoleDebugComponent: ConsoleDebugComponent
): void {
  addToQueue({
    abortSignal: abortSignalComponent.abortSignal,
    app: plugin.app,
    operationFn: (abortSignal) =>
      collectAttachmentsInAbstractFilesImpl(
        plugin,
        [plugin.app.vault.getRoot()],
        abortSignal,
        pluginSettingsComponent,
        consoleDebugComponent,
        abortSignalComponent
      ),
    operationName: t(($) => $.commands.collectAttachmentsEntireVault),
    timeoutInMilliseconds: pluginSettingsComponent.settings.getTimeoutInMilliseconds()
  });
}

export function collectAttachmentsInAbstractFiles(
  plugin: Plugin,
  abstractFiles: TAbstractFile[],
  abortSignalComponent: AbortSignalComponent,
  pluginSettingsComponent: PluginSettingsComponent,
  consoleDebugComponent: ConsoleDebugComponent
): void {
  addToQueue({
    abortSignal: abortSignalComponent.abortSignal,
    app: plugin.app,
    operationFn: (abortSignal) =>
      collectAttachmentsInAbstractFilesImpl(plugin, abstractFiles, abortSignal, pluginSettingsComponent, consoleDebugComponent, abortSignalComponent),
    operationName: t(($) => $.menuItems.collectAttachmentsInFile),
    timeoutInMilliseconds: pluginSettingsComponent.settings.getTimeoutInMilliseconds()
  });
}

export async function getProperAttachmentPath(params: GetProperAttachmentPathParams): Promise<null | string> {
  const attachmentFileContent = await params.plugin.app.vault.readBinary(params.attachmentFile);
  const newAttachmentName = params.pluginSettingsComponent.settings.shouldRenameCollectedAttachments
    ? makeFileName(
      await getGeneratedAttachmentFileBaseName(
        params.plugin,
        new Substitutions({
          actionContext: params.actionContext,
          attachmentFileContent,
          attachmentFileStat: params.attachmentFile.stat,
          cursorLine: isReferenceCache(params.reference) ? params.reference.position.start.line : 0,
          noteFilePath: params.noteFilePath,
          originalAttachmentFileName: params.attachmentFile.name,
          plugin: params.plugin,
          sequenceNumber: await params.plugin.getSequenceNumber(params.noteFilePath, params.attachmentFile.path)
        }),
        params.pluginSettingsComponent
      ),
      params.attachmentFile.extension
    )
    : params.attachmentFile.name;

  const newAttachmentFolderPath = await getAttachmentFolderFullPathForPath(
    params.plugin,
    params.actionContext,
    params.noteFilePath,
    newAttachmentName,
    params.pluginSettingsComponent,
    undefined,
    attachmentFileContent,
    params.attachmentFile.stat
  );
  const newAttachmentPath = join(newAttachmentFolderPath, newAttachmentName);

  if (params.attachmentFile.path === newAttachmentPath) {
    return null;
  }

  return newAttachmentPath;
}

export function isNoteEx(plugin: Plugin, pathOrFile: null | PathOrAbstractFile, pluginSettingsComponent: PluginSettingsComponent): boolean {
  if (!pathOrFile || !isNote(plugin.app, pathOrFile)) {
    return false;
  }

  const path = getPath(plugin.app, pathOrFile);
  return pluginSettingsComponent.settings.treatAsAttachmentExtensions.every((extension) => !path.endsWith(extension));
}

async function collectAttachmentsInAbstractFilesImpl(
  plugin: Plugin,
  abstractFiles: TAbstractFile[],
  abortSignal: AbortSignal,
  pluginSettingsComponent: PluginSettingsComponent,
  consoleDebugComponent: ConsoleDebugComponent,
  abortSignalComponent: AbortSignalComponent
): Promise<void> {
  abortSignal.throwIfAborted();
  const singleFile: null | TFile = abstractFiles.length === 1 && isFile(abstractFiles[0]) ? abstractFiles[0] : null;

  if (singleFile && pluginSettingsComponent.settings.isPathIgnored(singleFile.path)) {
    new Notice(t(($) => $.notice.notePathIsIgnored));
    console.warn(`Cannot collect attachments in the note as note path is ignored: ${singleFile.path}.`);
    return;
  }

  const canCollectAttachments = !!singleFile || (await confirm({
    app: plugin.app,
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
  consoleDebugComponent.consoleDebug(`Collect attachments in files:\n${abstractFiles.map((abstractFile) => abstractFile.path).join('\n')}`);
  const noteFilesSet = new Set<TFile>();

  for (const abstractFile of abstractFiles) {
    if (isFile(abstractFile) && isNote(plugin.app, abstractFile)) {
      noteFilesSet.add(abstractFile);
    }

    if (isFolder(abstractFile)) {
      Vault.recurseChildren(abstractFile, (child) => {
        if (isFile(child) && isNote(plugin.app, child)) {
          noteFilesSet.add(child);
        }
      });
    }
  }

  const noteFiles = Array.from(noteFilesSet);
  noteFiles.sort((a, b) => a.path.localeCompare(b.path));

  const ctx: CollectAttachmentContext = {};
  const abortController = new AbortController();

  const combinedAbortSignal = abortSignalAny(abortController.signal, abortSignalComponent.abortSignal);

  await loop({
    abortSignal: combinedAbortSignal,
    buildNoticeMessage: (noteFile, iterationStr) => t(($) => $.attachmentCollector.progressBar.message, { iterationStr, noteFilePath: noteFile.path }),
    items: noteFiles,
    processItem: async (noteFile) => {
      combinedAbortSignal.throwIfAborted();
      if (pluginSettingsComponent.settings.isPathIgnored(noteFile.path)) {
        console.warn(`Cannot collect attachments in the note as note path is ignored: ${noteFile.path}.`);
        return;
      }
      await collectAttachments(plugin, noteFile, ctx, combinedAbortSignal, pluginSettingsComponent);
      combinedAbortSignal.throwIfAborted();
      if (ctx.isAborted) {
        abortController.abort();
      }
    },
    progressBarTitle: `${plugin.manifest.name}: ${t(($) => $.attachmentCollector.progressBar.title)}`,
    shouldContinueOnError: true,
    shouldShowProgressBar: true
  });
}

async function getCanvasLinks(app: App, canvasFile: TFile): Promise<ReferenceCache[]> {
  const canvasData = await app.vault.readJson(canvasFile.path) as CanvasData;
  const paths = canvasData.nodes.filter((node) => node.type === 'file').map((node) => node.file);
  return paths.map((path) => ({
    link: path,
    original: path,
    position: {
      end: { col: 0, line: 0, loc: 0, offset: 0 },
      start: { col: 0, line: 0, loc: 0, offset: 0 }
    }
  }));
}

async function prepareAttachmentToMove(
  plugin: Plugin,
  reference: Reference,
  newNotePath: string,
  oldNotePath: string,
  oldAttachmentPaths: Set<string>,
  pluginSettingsComponent: PluginSettingsComponent
): Promise<AttachmentMoveResult | null> {
  const app = plugin.app;

  const oldAttachmentFile = extractLinkFile(app, reference, oldNotePath, true);

  if (!oldAttachmentFile) {
    return null;
  }

  if (isNoteEx(plugin, oldAttachmentFile, pluginSettingsComponent)) {
    return null;
  }

  if (oldAttachmentPaths.has(oldAttachmentFile.path)) {
    return null;
  }

  oldAttachmentPaths.add(oldAttachmentFile.path);

  if (oldAttachmentFile.deleted) {
    console.warn(`Skipping collecting attachment ${reference.link} as it could not be resolved.`);
    return null;
  }

  const newAttachmentPath = await getProperAttachmentPath({
    actionContext: ActionContext.CollectAttachments,
    attachmentFile: oldAttachmentFile,
    noteFilePath: newNotePath,
    plugin,
    pluginSettingsComponent,
    reference
  });

  return {
    newAttachmentPath,
    oldAttachmentPath: oldAttachmentFile.path
  };
}
