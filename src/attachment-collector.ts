import type {
  Reference,
  TAbstractFile
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import type { FileChange } from 'obsidian-dev-utils/obsidian/file-change';
import type { CanvasReference } from 'obsidian-dev-utils/obsidian/reference';
import type { ResourceLockComponent } from 'obsidian-dev-utils/obsidian/resource-lock';
import type { MaybeReturn } from 'obsidian-dev-utils/type';

import {
  App,
  setIcon,
  TFile,
  Vault
} from 'obsidian';
import { abortSignalAny } from 'obsidian-dev-utils/abort-controller';
import {
  createElAsync,
  createFragmentAsync
} from 'obsidian-dev-utils/html-element';
import {
  findAttachmentUnitFolderPath,
  rebasePathOntoFolder
} from 'obsidian-dev-utils/obsidian/attachment-unit-folder';
import { getCanvasReferences } from 'obsidian-dev-utils/obsidian/canvas';
import { applyFileChanges } from 'obsidian-dev-utils/obsidian/file-change';
import {
  isCanvasFile,
  isFile,
  isFolder,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { appendCodeBlock } from 'obsidian-dev-utils/obsidian/html-element';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  editLinks,
  extractLinkFile,
  updateLink
} from 'obsidian-dev-utils/obsidian/link';
import { loop } from 'obsidian-dev-utils/obsidian/loop';
import { renderInternalLink } from 'obsidian-dev-utils/obsidian/markdown';
import {
  getBacklinksForFileSafe,
  getCacheSafe,
  getLinks
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { addToQueue } from 'obsidian-dev-utils/obsidian/queue';
import {
  isCanvasTextNodeReference,
  referenceToFileChange
} from 'obsidian-dev-utils/obsidian/reference';
import {
  cleanupEmptyFolders,
  copySafe,
  renameSafe
} from 'obsidian-dev-utils/obsidian/vault';
import {
  basename,
  dirname,
  join
} from 'obsidian-dev-utils/path';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { NetworkImageDownloader } from './network-image-downloader.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { checkIsAttachmentUnitFolder } from './attachment-unit-folder-designation.ts';
import { selectMode } from './modals/collect-attachment-used-by-multiple-notes-modal.ts';
import { NoteOwnerResolver } from './note-owner-resolver.ts';
import { CollectAttachmentUsedByMultipleNotesMode } from './plugin-settings.ts';
import { isReferencedByRawPath } from './raw-path-reference.ts';
import { ActionContext } from './token-evaluator-context.ts';

interface AttachmentCollectorCollectAttachmentsParams {
  readonly abortSignal: AbortSignal;
  readonly context: CollectAttachmentContext;
  readonly note: TFile;
}

interface AttachmentCollectorConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly consoleDebugComponent: ConsoleDebugComponent;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly networkImageDownloader: NetworkImageDownloader;
  readonly pluginName: string;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly resourceLockComponent: null | ResourceLockComponent;
}

interface AttachmentCollectorPrepareAttachmentToMoveForNoteParams {
  readonly attachmentMoveResult: AttachmentMoveResult;
  readonly newNotePath: string;
  readonly reference: Reference;
  readonly sequenceNumberByAttachmentPath: ReadonlyMap<string, number>;
}

interface AttachmentCollectorPrepareAttachmentToMoveParams {
  readonly movedUnitFolderPaths: ReadonlyMap<string, string>;
  readonly newNotePath: string;
  readonly oldAttachmentPaths: Set<string>;
  readonly oldNotePath: string;
  readonly reference: Reference;
  readonly sequenceNumberByAttachmentPath: ReadonlyMap<string, number>;
}

interface AttachmentCollectorRewriteMovedCanvasReferencesParams {
  readonly abortSignal: AbortSignal;
  readonly canvasReferenceTargets: readonly CanvasReferenceTarget[];
  readonly movedAttachments: ReadonlyMap<string, MovedAttachment>;
  readonly note: TFile;
}

interface AttachmentCollectorSkipAttachmentReferencedByRawPathParams {
  readonly abortSignal: AbortSignal;
  readonly attachmentPath: string;
  readonly indexedBacklinkPaths: ReadonlySet<string>;
}

interface AttachmentMoveResult {
  readonly newAttachmentPath: null | string;
  readonly oldAttachmentPath: string;
  /**
   * Set when the attachment sits inside a folder the user designated as a single unit, in which case
   * the whole folder travels and this attachment simply comes along inside it.
   */
  readonly unitFolderPath: null | string;
}

interface CanvasReferenceTarget {
  readonly oldTargetPath: string | undefined;
  readonly reference: CanvasReference;
}

interface CollectAttachmentContext {
  collectAttachmentUsedByMultipleNotesMode?: CollectAttachmentUsedByMultipleNotesMode;
  isAborted?: boolean;

  /**
   * Whether to name the higher-priority notes when the priority list hands an attachment to a note
   * other than the one being collected (issue #75).
   *
   * Set only for a run over a single note - the `Collect attachments in current note` command - where
   * the user is asking about that one note and the answer is worth a notice. A folder-wide or
   * vault-wide run visits notes the user never singled out, so the same report there would be a box
   * per attachment.
   */
  shouldReportHigherPriorityNotes?: boolean;
}

interface MovedAttachment {
  readonly newAttachmentPath: string;
  readonly wasCopied: boolean;
}

export class AttachmentCollector {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly consoleDebugComponent: ConsoleDebugComponent;
  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly networkImageDownloader: NetworkImageDownloader;
  private readonly noteOwnerResolver: NoteOwnerResolver;
  private readonly pluginName: string;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly resourceLockComponent: null | ResourceLockComponent;

  public constructor(params: AttachmentCollectorConstructorParams) {
    this.abortSignalComponent = params.abortSignalComponent;
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.consoleDebugComponent = params.consoleDebugComponent;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.networkImageDownloader = params.networkImageDownloader;
    this.resourceLockComponent = params.resourceLockComponent;
    this.pluginName = params.pluginName;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.noteOwnerResolver = new NoteOwnerResolver({
      app: params.app,
      handedOverSettingsComponent: params.handedOverSettingsComponent,
      pluginSettingsComponent: params.pluginSettingsComponent
    });
  }

  public collectAttachmentsEntireVault(): void {
    addToQueue({
      abortSignal: this.abortSignalComponent.abortSignal,
      operationFunction: (abortSignal) =>
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
      operationFunction: (abortSignal) => this.collectAttachmentsInAbstractFilesImpl(abstractFiles, abortSignal),
      operationName: t(($) => $.menuItems.collectAttachmentsInFile),
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
    });
  }

  /**
   * Builds the notice naming the notes that outrank the one being collected, so the user can open the
   * note that really owns the attachment instead of only being told that one exists (issue #75).
   *
   * @param attachmentPath - The shared attachment's vault-relative path.
   * @param notePaths - The higher-priority notes' vault-relative paths.
   * @returns The notice content.
   */
  private buildHigherPriorityNotesNoticeMessage(attachmentPath: string, notePaths: readonly string[]): Promise<DocumentFragment> {
    return createFragmentAsync(async (f) => {
      f.appendText(t(($) => $.notice.attachmentReferencedByHigherPriorityNotes.part1));
      f.appendText(' ');
      f.append(
        await renderInternalLink({
          app: this.app,
          pathOrAbstractFile: attachmentPath
        })
      );
      f.appendText(' ');
      f.appendText(t(($) => $.notice.attachmentReferencedByHigherPriorityNotes.part2));
      f.append(
        // The class carries no styling; it is how an integration test addresses the list.
        await createElAsync('ul', { cls: 'custom-attachment-location-higher-priority-notes-list' }, async (ul) => {
          for (const notePath of notePaths) {
            ul.append(
              await createElAsync('li', {}, async (li) => {
                li.append(
                  await renderInternalLink({
                    app: this.app,
                    pathOrAbstractFile: notePath
                  })
                );
              })
            );
          }
        })
      );
    });
  }

  private async collectAttachments(params: AttachmentCollectorCollectAttachmentsParams): Promise<void> {
    const app = this.app;
    const pluginNoticeComponent = this.pluginNoticeComponent;
    const pluginSettingsComponent = this.pluginSettingsComponent;
    const resourceLockComponent = this.resourceLockComponent;

    params.abortSignal.throwIfAborted();
    if (params.context.isAborted) {
      return;
    }

    const notice = this.pluginNoticeComponent.showNotice(t(($) => $.notice.collectingAttachments, { noteFilePath: params.note.path }), {
      isPermanent: true
    });

    try {
      const isCanvas = isCanvasFile(params.note);

      const oldAttachmentPaths = new Set<string>();

      const cache = await getCacheSafe(app, params.note);
      params.abortSignal.throwIfAborted();

      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Could be changed in await call.
      if (params.context.isAborted) {
        return;
      }

      if (!cache) {
        return;
      }

      const links = isCanvas ? await getCanvasReferences(app, params.note) : getLinks({ cache });
      params.abortSignal.throwIfAborted();

      // Snapshot the attachment numbering from the pristine note, before any move rewrites its links.
      const sequenceNumberByAttachmentPath = await this.attachmentPathManager.getSequenceNumberMap(params.note.path);
      params.abortSignal.throwIfAborted();

      // Folders vacated by moving attachments out of them; cleaned up after the loop honoring emptyFolderBehavior.
      const oldParentFolderPaths = new Set<string>();

      // Canvas references resolved to their pre-move target paths.
      // Obsidian does not index canvas into the metadata cache, so canvas embeds cannot be rewritten via `editLinks`.
      // After the loop we rewrite every canvas reference pointing to a moved attachment.
      // File-node moves are additionally rewritten by Obsidian core on rename (see below).
      const canvasReferenceTargets = isCanvas
        ? (links as CanvasReference[]).map((reference) => ({
          oldTargetPath: extractLinkFile({
            app,
            link: reference,
            shouldAllowNonExistingFile: true,
            sourcePathOrFile: params.note
          })?.path,
          reference
        }))
        : [];

      // Attachments relocated during this note's collection: old path -> new path + whether it was copied.
      // Obsidian core rewrites a canvas file-node prop when the attachment is moved (renamed) but not when copied.
      const movedAttachments = new Map<string, MovedAttachment>();

      // Attachment unit folders already carried away during this note's collection: old path -> new path.
      // One folder holds many attachments, so the remaining links into it are already satisfied.
      const movedUnitFolderPaths = new Map<string, string>();

      for (const link of links) {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Could be changed in await call.
        if (params.context.isAborted) {
          return;
        }

        let attachmentMoveResult = await this.prepareAttachmentToMove({
          movedUnitFolderPaths,
          newNotePath: params.note.path,
          oldAttachmentPaths,
          oldNotePath: params.note.path,
          reference: link,
          sequenceNumberByAttachmentPath
        });
        params.abortSignal.throwIfAborted();
        if (!attachmentMoveResult) {
          continue;
        }

        if (this.pluginSettingsComponent.settings.isExcludedFromAttachmentCollecting(attachmentMoveResult.oldAttachmentPath)) {
          console.warn(`Skipping collecting attachment ${attachmentMoveResult.oldAttachmentPath} as it is excluded from attachment collecting.`);
          continue;
        }

        const backlinks = await getBacklinksForFileSafe({
          app: this.app,
          pathOrFile: attachmentMoveResult.oldAttachmentPath,
          timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
        });
        params.abortSignal.throwIfAborted();
        if (
          await this.skipAttachmentReferencedByRawPath({
            abortSignal: params.abortSignal,
            attachmentPath: attachmentMoveResult.oldAttachmentPath,
            indexedBacklinkPaths: new Set(backlinks.keys())
          })
        ) {
          params.abortSignal.throwIfAborted();
          continue;
        }
        params.abortSignal.throwIfAborted();

        const relevantBacklinks = backlinks.keys().filter((backlink) => !pluginSettingsComponent.settings.isExcludedFromMultipleNotesCheck(backlink));
        if (relevantBacklinks.length > 1) {
          const backlinksSorted = relevantBacklinks.sort((a, b) => a.localeCompare(b));

          /*
           * A configured priority answers "which of these notes owns it" outright, so the mode
           * dispatch below never runs. Note this can move the attachment into a note OTHER than the
           * one being collected — that is the point of the setting, and why it is empty by default.
           *
           * The ambiguity that mode exists for is "several notes at the HIGHEST rank", not "several
           * notes". So a named winner short-circuits unconditionally, including when it turns out
           * there is nothing to move because the winner already holds the attachment (issue #73):
           * an unambiguous collect must stay as quiet as a singly-referenced one.
           */
          const priorityWinnerNotePath = this.noteOwnerResolver.pickOwnerNotePath(backlinksSorted);
          if (priorityWinnerNotePath) {
            const priorityResult = await this.prepareAttachmentToMoveForNote({
              attachmentMoveResult,
              newNotePath: priorityWinnerNotePath,
              reference: link,
              sequenceNumberByAttachmentPath
            });
            params.abortSignal.throwIfAborted();
            if (priorityResult) {
              // eslint-disable-next-line require-atomic-updates -- Matches how the surrounding code reassigns this; a single note's links are collected in sequence.
              attachmentMoveResult = priorityResult;
              this.consoleDebugComponent.consoleDebug(
                attachmentMoveResult.newAttachmentPath
                  ? `Collecting attachment ${attachmentMoveResult.oldAttachmentPath} into ${priorityWinnerNotePath} as the highest-priority referencing note.`
                  : `Leaving attachment ${attachmentMoveResult.oldAttachmentPath} where it is,`
                    + ` as the highest-priority referencing note ${priorityWinnerNotePath} already holds it.`
              );
              await registerMoveAttachment();
              params.abortSignal.throwIfAborted();

              /*
               * The list settling the ownership does not mean the user can see who won. Collecting
               * from a note the list ranked below the others hands the attachment away in silence, so
               * name the notes that outrank this one (issue #75). Both branches of the message above
               * report it: an attachment the winner already holds is the reporter's own case.
               *
               * Every note ranked above the collected one is named, not only the winner, because the
               * question being answered is "who outranks me?" rather than "who won?".
               */
              const higherPriorityNotePaths = params.context.shouldReportHigherPriorityNotes
                ? this.noteOwnerResolver.filterHigherPriorityNotePaths(backlinksSorted, params.note.path)
                : [];
              if (higherPriorityNotePaths.length > 0) {
                // The log names exactly the notes the notice does, so the two can never disagree.
                const higherPriorityNotePathsString = higherPriorityNotePaths.map((notePath) => `- ${notePath}`).join('\n');
                this.consoleDebugComponent.consoleDebug(
                  `Attachment ${attachmentMoveResult.oldAttachmentPath} is also referenced by notes ranked above ${params.note.path}:\n${higherPriorityNotePathsString}`
                );
                pluginNoticeComponent.showNotice(
                  await this.buildHigherPriorityNotesNoticeMessage(attachmentMoveResult.oldAttachmentPath, higherPriorityNotePaths),
                  { shouldHideOnClick: false }
                );
                params.abortSignal.throwIfAborted();
              }
            } else {
              // The winner is settled either way; the attachment itself is what went missing.
              console.warn(`Skipping collecting attachment ${attachmentMoveResult.oldAttachmentPath} as it could not be resolved.`);
            }
            continue;
          }

          // Reaching here means the list named nobody, so there is always a reason to report.
          const noPriorityWinnerReason = this.noteOwnerResolver.findNoPriorityWinnerReason(backlinksSorted);

          /*
           * The DECISION above is made over every referencing note; only the REPORT below narrows.
           * The notes tying for the best rank are the whole of the ambiguity, so a note the list
           * ranked beneath them cannot resolve anything and is left out of both the dialog and the
           * log (issue #74). When the list decides nothing — empty, or matching no note — every note
           * ties and the list is unchanged.
           */
          const topRankBacklinks = this.noteOwnerResolver.filterTopRankNotePaths(backlinksSorted);
          const backlinksString = topRankBacklinks.map((backlink) => `- ${backlink}`).join('\n');

          async function shouldCollectWithMode(
            collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode
          ): Promise<boolean> {
            params.abortSignal.throwIfAborted();
            let result = ensureNonNullable(attachmentMoveResult);

            switch (collectAttachmentUsedByMultipleNotesMode) {
              case CollectAttachmentUsedByMultipleNotesMode.Cancel: {
                console.error(
                  `Cancelling collecting attachments, as attachment ${result.oldAttachmentPath} is referenced by multiple notes.\n${backlinksString}`
                );
                if (pluginSettingsComponent.settings.collectAttachmentUsedByMultipleNotesMode === CollectAttachmentUsedByMultipleNotesMode.Cancel) {
                  await selectMode({
                    app,
                    attachmentPath: result.oldAttachmentPath,
                    backlinks: topRankBacklinks,
                    isCancelMode: true,
                    noPriorityWinnerReason
                  });
                }
                // eslint-disable-next-line require-atomic-updates -- Cannot avoid.
                params.context.isAborted = true;
                return false;
              }
              case CollectAttachmentUsedByMultipleNotesMode.Copy: {
                if (!result.newAttachmentPath) {
                  console.warn(`Skipping collecting attachment ${result.oldAttachmentPath} as it is already in the destination folder.`);
                  return false;
                }
                if (result.unitFolderPath) {
                  // Copying the lone file out of a unit folder produces exactly the broken attachment
                  // The unit designation exists to prevent, and copying the whole tree behind the
                  // Other notes' backs is worse. Leave it where every note can still reach it.
                  console.warn(
                    `Skipping collecting attachment ${result.oldAttachmentPath} as it belongs to the attachment unit folder ${result.unitFolderPath}`
                      + ` and is referenced by multiple notes.\n${backlinksString}`
                  );
                  pluginNoticeComponent.showNotice(t(($) => $.notice.attachmentUnitFolderUsedByMultipleNotes, {
                    attachmentPath: result.oldAttachmentPath,
                    unitFolderPath: result.unitFolderPath
                  }));
                  return false;
                }
                // eslint-disable-next-line require-atomic-updates -- Ignore possible race condition.
                result = {
                  ...result,
                  newAttachmentPath: await copySafe({
                    app,
                    newPath: result.newAttachmentPath,
                    oldPathOrFile: result.oldAttachmentPath
                  })
                };
                movedAttachments.set(result.oldAttachmentPath, {
                  newAttachmentPath: ensureNonNullable(result.newAttachmentPath),
                  wasCopied: true
                });
                await editLinks({
                  app,
                  linkConverter: (link2): MaybeReturn<string> => {
                    const linkFile = extractLinkFile({
                      app,
                      link: link2,
                      sourcePathOrFile: params.note
                    });
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
                  },
                  pathOrFile: params.note,
                  pluginNoticeComponent,
                  resourceLockComponent
                });
                break;
              }
              case CollectAttachmentUsedByMultipleNotesMode.Move: {
                if (!result.newAttachmentPath) {
                  console.warn(`Skipping collecting attachment ${result.oldAttachmentPath} as it is already in the destination folder.`);
                  return false;
                }
                await registerMoveAttachment();
                params.abortSignal.throwIfAborted();
                break;
              }
              case CollectAttachmentUsedByMultipleNotesMode.Prompt: {
                const { mode, shouldUseSameActionForOtherProblematicAttachments } = await selectMode({
                  app,
                  attachmentPath: result.oldAttachmentPath,
                  backlinks: topRankBacklinks,
                  noPriorityWinnerReason
                });
                if (shouldUseSameActionForOtherProblematicAttachments) {
                  // eslint-disable-next-line require-atomic-updates -- Cannot avoid.
                  params.context.collectAttachmentUsedByMultipleNotesMode = mode;
                }
                // eslint-disable-next-line unicorn/no-useless-recursion -- A single re-dispatch after the user picks a mode in the modal; a loop would obscure the switch.
                return shouldCollectWithMode(mode);
              }
              case CollectAttachmentUsedByMultipleNotesMode.Skip: {
                console.warn(
                  `Skipping collecting attachment ${result.oldAttachmentPath} as it is referenced by multiple notes.\n${backlinksString}`
                );
                return false;
              }
              default: {
                throw new Error(
                  `Unknown collect attachment used by multiple notes mode: ${pluginSettingsComponent.settings.collectAttachmentUsedByMultipleNotesMode}`
                );
              }
            }

            return true;
          }

          if (
            !await shouldCollectWithMode(
              params.context.collectAttachmentUsedByMultipleNotesMode ?? pluginSettingsComponent.settings.collectAttachmentUsedByMultipleNotesMode
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

          /*
           * When the attachment travels inside its unit folder, the folder VACATED is the unit folder's
           * own parent: the attachment's own parent is carried away with the tree and no longer exists
           * to be cleaned up, so recording it leaves the real parent unswept (issue #69).
           */
          oldParentFolderPaths.add(dirname(attachmentMoveResult.unitFolderPath ?? attachmentMoveResult.oldAttachmentPath));

          const newAttachmentPath = attachmentMoveResult.unitFolderPath
            ? await moveUnitFolder(attachmentMoveResult.unitFolderPath, attachmentMoveResult.oldAttachmentPath, attachmentMoveResult.newAttachmentPath)
            : await renameSafe({
              app,
              newPath: attachmentMoveResult.newAttachmentPath,
              oldPathOrAbstractFile: attachmentMoveResult.oldAttachmentPath
            });

          if (!newAttachmentPath) {
            return;
          }

          attachmentMoveResult = {
            ...attachmentMoveResult,
            newAttachmentPath
          };
          movedAttachments.set(attachmentMoveResult.oldAttachmentPath, {
            newAttachmentPath,
            wasCopied: false
          });
        }

        /**
         * Moves the whole designated folder and reports where the linked attachment ended up inside
         * it. The folder lands in the note's attachment folder — the same folder the lone file would
         * have gone to — under its own name, so the tree's internal shape is untouched and the
         * relative links inside it keep working.
         */
        async function moveUnitFolder(unitFolderPath: string, oldAttachmentPath: string, plannedAttachmentPath: string): Promise<null | string> {
          const unitFolder = app.vault.getFolderByPath(unitFolderPath);
          if (!unitFolder) {
            console.warn(`Skipping collecting attachment ${oldAttachmentPath} as its attachment unit folder ${unitFolderPath} could not be resolved.`);
            return null;
          }

          const newUnitFolderPath = await renameSafe({
            app,
            newPath: join(dirname(plannedAttachmentPath), basename(unitFolderPath)),
            oldPathOrAbstractFile: unitFolder
          });
          movedUnitFolderPaths.set(unitFolderPath, newUnitFolderPath);

          // The whole tree moved, so the attachment is wherever it was inside it, only rebased.
          return rebasePathOntoFolder({
            newFolderPath: newUnitFolderPath,
            oldFolderPath: unitFolderPath,
            path: oldAttachmentPath
          });
        }
      }

      if (isCanvas) {
        await this.rewriteMovedCanvasReferences({
          abortSignal: params.abortSignal,
          canvasReferenceTargets,
          movedAttachments,
          note: params.note
        });
      }

      await cleanupEmptyFolders({
        app,
        emptyFolderBehavior: this.handedOverSettingsComponent.settings.emptyFolderBehavior,
        folderPaths: [...oldParentFolderPaths]
      });

      await this.networkImageDownloader.downloadNetworkImagesForNote(params.note);
    } finally {
      notice.hide();
    }
  }

  private async collectAttachmentsInAbstractFilesImpl(abstractFiles: TAbstractFile[], abortSignal: AbortSignal): Promise<void> {
    abortSignal.throwIfAborted();
    const singleFile: null | TFile = abstractFiles.length === 1 && isFile(abstractFiles[0]) ? abstractFiles[0] : null;

    if (singleFile && this.handedOverSettingsComponent.isPathIgnored(singleFile.path)) {
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.notePathIsIgnored));
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

    const noteFiles = [...noteFilesSet];
    noteFiles.sort((a, b) => a.path.localeCompare(b.path));

    const context: CollectAttachmentContext = { shouldReportHigherPriorityNotes: !!singleFile };
    const abortController = new AbortController();

    const combinedAbortSignal = abortSignalAny(abortController.signal, this.abortSignalComponent.abortSignal);

    await loop({
      abortSignal: combinedAbortSignal,
      buildNoticeMessage: ({ item, iterationString }) => t(($) => $.attachmentCollector.progressBar.message, { iterationString, noteFilePath: item.path }),
      items: noteFiles,
      pluginNoticeComponent: this.pluginNoticeComponent,
      processItem: async (noteFile) => {
        combinedAbortSignal.throwIfAborted();
        if (this.handedOverSettingsComponent.isPathIgnored(noteFile.path)) {
          console.warn(`Cannot collect attachments in the note as note path is ignored: ${noteFile.path}.`);
          return;
        }
        await this.collectAttachments({
          abortSignal: combinedAbortSignal,
          context,
          note: noteFile
        });
        combinedAbortSignal.throwIfAborted();
        if (context.isAborted) {
          abortController.abort();
        }
      },
      progressBarTitle: `${this.pluginName}: ${t(($) => $.attachmentCollector.progressBar.title)}`,
      shouldContinueOnError: true,
      shouldShowProgressBar: true
    });
  }

  private async prepareAttachmentToMove(params: AttachmentCollectorPrepareAttachmentToMoveParams): Promise<AttachmentMoveResult | null> {
    const oldAttachmentFile = extractLinkFile({
      app: this.app,
      link: params.reference,
      shouldAllowNonExistingFile: true,
      sourcePathOrFile: params.oldNotePath
    });

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

    // An earlier link in this same note may have already carried this attachment away inside its unit
    // Folder. The link snapshot still names the old path, so without this the file reads as
    // Unresolvable and would be reported as a broken link rather than as work already done.
    for (const movedUnitFolderPath of params.movedUnitFolderPaths.keys()) {
      if (oldAttachmentFile.path.startsWith(`${movedUnitFolderPath}/`)) {
        return null;
      }
    }

    if (oldAttachmentFile.deleted) {
      console.warn(`Skipping collecting attachment ${params.reference.link} as it could not be resolved.`);
      return null;
    }

    const newAttachmentPath = await this.attachmentPathManager.getProperAttachmentPath({
      actionContext: ActionContext.CollectAttachments,
      attachmentFile: oldAttachmentFile,
      noteFilePath: params.newNotePath,
      reference: params.reference,
      sequenceNumber: params.sequenceNumberByAttachmentPath.get(oldAttachmentFile.path) ?? 0
    });

    return {
      newAttachmentPath,
      oldAttachmentPath: oldAttachmentFile.path,
      /*
       * Read back through the published designation rather than straight off the settings, so the
       * collecting commands and the plugin that owns the delete interception decide from one answer.
       * Two plugins deciding separately what a single attachment is would leave a folder kept whole
       * by one and torn apart by the other.
       */
      unitFolderPath: findAttachmentUnitFolderPath({
        attachmentPath: oldAttachmentFile.path,
        checkIsAttachmentUnitFolder: (folderPath) =>
          checkIsAttachmentUnitFolder({
            folderPath,
            vault: this.app.vault
          })
      })
    };
  }

  /**
   * Recomputes where an attachment belongs when a note other than the one being collected has won it
   * on priority. Only the destination changes; the attachment and its unit folder are untouched.
   *
   * A `null` RESULT means the attachment file itself could not be resolved — the only real failure
   * here. A null `newAttachmentPath` inside the result is not one: it says the winner already holds
   * the attachment, so the collect is done rather than stuck. Conflating the two is what made an
   * unambiguous collect report the shared-attachment ambiguity (issue #73).
   */
  private async prepareAttachmentToMoveForNote(params: AttachmentCollectorPrepareAttachmentToMoveForNoteParams): Promise<AttachmentMoveResult | null> {
    const attachmentFile = this.app.vault.getFileByPath(params.attachmentMoveResult.oldAttachmentPath);
    if (!attachmentFile) {
      return null;
    }

    const newAttachmentPath = await this.attachmentPathManager.getProperAttachmentPath({
      actionContext: ActionContext.CollectAttachments,
      attachmentFile,
      noteFilePath: params.newNotePath,
      reference: params.reference,
      sequenceNumber: params.sequenceNumberByAttachmentPath.get(attachmentFile.path) ?? 0
    });

    return {
      ...params.attachmentMoveResult,
      newAttachmentPath
    };
  }

  private async rewriteMovedCanvasReferences(params: AttachmentCollectorRewriteMovedCanvasReferencesParams): Promise<void> {
    // Rewrite every canvas reference pointing to a moved attachment.
    // Text-node embeds always need rewriting (Obsidian core never touches them).
    // File-node props need it only for copies (moves are rewritten by Obsidian core).
    const changes: FileChange[] = [];
    for (const { oldTargetPath, reference } of params.canvasReferenceTargets) {
      if (oldTargetPath === undefined) {
        continue;
      }

      const moved = params.movedAttachments.get(oldTargetPath);
      if (!moved) {
        continue;
      }

      if (isCanvasTextNodeReference(reference)) {
        const newContent = updateLink({
          app: this.app,
          link: reference.originalReference,
          newSourcePathOrFile: params.note,
          newTargetPathOrFile: moved.newAttachmentPath,
          oldSourcePathOrFile: params.note,
          oldTargetPathOrFile: oldTargetPath
        });
        changes.push(referenceToFileChange(reference, newContent));
      } else if (moved.wasCopied) {
        // Canvas file-node prop: Obsidian core rewrites it on rename (move) but not on copy.
        changes.push(referenceToFileChange(reference, moved.newAttachmentPath));
      }
    }

    if (changes.length > 0) {
      await applyFileChanges({
        app: this.app,
        changesProvider: changes,
        pathOrFile: params.note,
        pluginNoticeComponent: this.pluginNoticeComponent,
        resourceLockComponent: this.resourceLockComponent
      });
      params.abortSignal.throwIfAborted();
    }
  }

  /**
   * Opt-in safety net for issue #46: when enabled, scans every note's raw text for a non-indexed
   * reference to the attachment (e.g. another plugin's custom syntax or raw HTML). If one is found,
   * warns, shows a notice, and returns `true` so the caller skips relocating the attachment - erring
   * toward NOT moving, since a false positive merely leaves it un-collected while a false negative
   * could relocate a still-used attachment and lose it. Does NOT rewrite the non-standard reference.
   */
  private async skipAttachmentReferencedByRawPath(params: AttachmentCollectorSkipAttachmentReferencedByRawPathParams): Promise<boolean> {
    if (!this.pluginSettingsComponent.settings.shouldSkipCollectingAttachmentsReferencedByRawPath) {
      return false;
    }

    for (const noteFile of this.app.vault.getMarkdownFiles()) {
      params.abortSignal.throwIfAborted();
      // Notes with an indexed link to the attachment are already accounted for by the backlink-based checks.
      if (params.indexedBacklinkPaths.has(noteFile.path)) {
        continue;
      }

      const content = await this.app.vault.cachedRead(noteFile);
      if (!isReferencedByRawPath({ attachmentPath: params.attachmentPath, content })) {
        continue;
      }

      console.warn(
        `Skipping collecting attachment ${params.attachmentPath} as it is referenced by a raw path (not an indexed link) in ${noteFile.path}.`
      );
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.attachmentReferencedByRawPath, {
        attachmentPath: params.attachmentPath,
        noteFilePath: noteFile.path
      }));
      return true;
    }

    return false;
  }
}
