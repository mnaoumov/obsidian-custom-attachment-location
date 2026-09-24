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
import { noop } from 'obsidian-dev-utils/function';
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
import {
  addToQueue,
  addToQueueAndWait
} from 'obsidian-dev-utils/obsidian/queue';
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

interface AttachmentCollectorReportNothingCollectedParams {
  readonly alreadyInPlaceAttachmentPaths: ReadonlySet<string>;
  readonly context: CollectAttachmentContext;
  readonly examinedAttachmentPaths: ReadonlySet<string>;
  readonly notePath: string;
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
   * Whether this run was started by an edit to the note rather than by the user, which happens when
   * `Collect attachments automatically` is on.
   *
   * Such a run shows no progress notice, because it repeats on every save of the note.
   */
  isAutomaticRun?: boolean;

  /**
   * Whether this run targets a single note - the `Collect attachments in current note` command.
   *
   * It is the condition every per-note REPORT hangs off, rather than a flag per report, because they
   * all answer the same question the same way: the user singled out one note and is owed an answer
   * about it, while a folder-wide or vault-wide run visits notes they never named, where the same
   * report would be a box per attachment. Two reports read it today - the higher-priority notes the
   * list handed an attachment to (issue #75), and a run that moved nothing at all (issue #81).
   */
  isSingleNoteRun?: boolean;
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

  /**
   * Collects the attachments of a note that has just changed, for `Collect attachments automatically`.
   *
   * Queued like the commands, so it cannot interleave with a collect the user started. A note this plugin
   * leaves alone is skipped without the notice the command shows, since nobody asked for this run.
   *
   * @param note - The note that changed.
   */
  public collectAttachmentsAutomatically(note: TFile): void {
    if (this.handedOverSettingsComponent.isPathIgnored(note.path)) {
      return;
    }

    addToQueue({
      abortSignal: this.abortSignalComponent.abortSignal,
      operationFunction: (abortSignal) =>
        this.collectAttachments({
          abortSignal,
          context: { isAutomaticRun: true },
          note
        }),
      operationName: t(($) => $.menuItems.collectAttachmentsInFile),
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getTimeoutInMilliseconds()
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
   * The same queued collect as {@link collectAttachmentsInAbstractFiles}, settling once it has finished — the
   * shape the published API hands another plugin, so it can sequence on the collect.
   *
   * @param abstractFiles - The notes, or folders of notes, to collect attachments for.
   * @returns A promise that settles once the collect has finished.
   */
  public async collectAttachmentsInAbstractFilesAndWait(abstractFiles: TAbstractFile[]): Promise<void> {
    await addToQueueAndWait({
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

  /**
   * Explains a `Collect attachments in current note` run that moved nothing (issue #81).
   *
   * The command legitimately does nothing when every attachment already sits where this note would
   * put it, and it used to say so only to the console - the reporter read the run as inert and filed
   * a bug against it. The second half names the one configuration that makes the outcome inevitable
   * rather than incidental: renaming collected attachments is ON while the template that would give
   * them a new name is EMPTY, which pins each name to the one it already has, leaving the folder as
   * the only thing that could ever differ.
   *
   * @param notePath - The note the run was over.
   * @returns The notice content.
   */
  private buildNothingToCollectNoticeMessage(notePath: string): DocumentFragment {
    const settings = this.pluginSettingsComponent.settings;
    return createFragment((f) => {
      f.appendText(t(($) => $.notice.nothingToCollect.part1, { noteFilePath: notePath }));

      if (!settings.shouldRenameCollectedAttachments || settings.collectedAttachmentFileName) {
        return;
      }

      f.createEl('br');
      f.appendText(t(($) => $.notice.nothingToCollect.part2));
      f.appendText(' ');
      appendCodeBlock(f, t(($) => $.pluginSettingsTab.collectedAttachmentFileName.name));
      f.appendText(' ');
      f.appendText(t(($) => $.notice.nothingToCollect.part3));
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

    const hideCollectingNotice = this.showCollectingNotice(params.context, params.note.path);

    try {
      const isCanvas = isCanvasFile(params.note);

      const oldAttachmentPaths = new Set<string>();

      const cache = await getCacheSafe(app, params.note);
      params.abortSignal.throwIfAborted();

      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Could be changed in await call.
      if (params.context.isAborted || !cache) {
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

      // The attachments this note examined, and those of them left exactly where they already were.
      // `shouldReportNothingCollected` compares the two at the end of the run.
      const examinedAttachmentPaths = new Set<string>();
      const alreadyInPlaceAttachmentPaths = new Set<string>();

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

        examinedAttachmentPaths.add(attachmentMoveResult.oldAttachmentPath);

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

        if (this.needsMultipleNotesHandling(attachmentMoveResult.oldAttachmentPath, relevantBacklinks.length)) {
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
              const higherPriorityNotePaths = params.context.isSingleNoteRun
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
                  alreadyInPlaceAttachmentPaths.add(result.oldAttachmentPath);
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
                    return linkFile?.path === result.oldAttachmentPath
                      ? updateLink({
                        app,
                        link: link2,
                        newSourcePathOrFile: params.note,
                        newTargetPathOrFile: ensureNonNullable(result.newAttachmentPath),
                        oldSourcePathOrFile: params.note,
                        oldTargetPathOrFile: result.oldAttachmentPath
                      })
                      : undefined;
                  },
                  pathOrFile: params.note,
                  pluginNoticeComponent,
                  resourceLockComponent
                });
                break;
              }
              case CollectAttachmentUsedByMultipleNotesMode.Move: {
                if (!result.newAttachmentPath) {
                  alreadyInPlaceAttachmentPaths.add(result.oldAttachmentPath);
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
          this.reportAttachmentAlreadyInPlace(attachmentMoveResult, alreadyInPlaceAttachmentPaths);
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

      /*
       * A run that moved nothing reported itself only to the console, which is what made the command
       * read as inert (issue #81). The notice does not hide on click, because a message explaining an
       * absence of change, and naming a setting to check, is worth more than the few seconds an
       * ordinary notice lasts.
       */
      this.reportNothingCollected({
        alreadyInPlaceAttachmentPaths,
        context: params.context,
        examinedAttachmentPaths,
        notePath: params.note.path
      });
    } finally {
      hideCollectingNotice();
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

    const context: CollectAttachmentContext = { isSingleNoteRun: !!singleFile };
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

  /**
   * Whether this attachment has to go through the multiple-notes mode at all.
   *
   * Two independent reasons to say no, and they are different axes on purpose. The backlink count has already had
   * the excluded NOTES filtered out of it by the caller — notes that do not count as a second referrer. This adds
   * the other half: a file type the user has declared deliberately shared never asks the question, however many
   * notes reference it (issue #80). Exempt, it takes the same branch a singly-referenced attachment takes —
   * collected, with Obsidian rewriting every note that points at it.
   *
   * A method of its own rather than a second operand in the caller's `if`, because `collectAttachments` sits on the
   * complexity ceiling and this keeps the reason for each half readable.
   *
   * @param attachmentPath - The vault-relative path of the attachment being collected.
   * @param relevantBacklinkCount - How many notes still count as referring to it.
   * @returns `true` when the configured multiple-notes mode should run.
   */
  private needsMultipleNotesHandling(attachmentPath: string, relevantBacklinkCount: number): boolean {
    return !this.pluginSettingsComponent.settings.isExtensionExcludedFromMultipleNotesCheck(attachmentPath) && relevantBacklinkCount > 1;
  }

  private async prepareAttachmentToMove(params: AttachmentCollectorPrepareAttachmentToMoveParams): Promise<AttachmentMoveResult | null> {
    const oldAttachmentFile = extractLinkFile({
      app: this.app,
      link: params.reference,
      shouldAllowNonExistingFile: true,
      sourcePathOrFile: params.oldNotePath
    });

    if (!oldAttachmentFile || this.pluginSettingsComponent.isNoteEx(oldAttachmentFile) || params.oldAttachmentPaths.has(oldAttachmentFile.path)) {
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
        app: this.app,
        attachmentPath: oldAttachmentFile.path
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

  /**
   * Records, and reports to the console, an attachment left exactly where it already was.
   *
   * The singly-referenced path used to say NOTHING here - not even a console line, while both
   * multiple-notes branches warned (issue #81). It is the commonest attachment of all, so a user
   * reading the console to find out why the command did nothing met the one case that had never
   * reported itself.
   *
   * @param result - The attachment's move result; a null `newAttachmentPath` is what says it stays.
   * @param alreadyInPlaceAttachmentPaths - The run's set of attachments left where they were.
   */
  private reportAttachmentAlreadyInPlace(result: AttachmentMoveResult, alreadyInPlaceAttachmentPaths: Set<string>): void {
    if (result.newAttachmentPath) {
      return;
    }

    alreadyInPlaceAttachmentPaths.add(result.oldAttachmentPath);
    console.warn(`Skipping collecting attachment ${result.oldAttachmentPath} as it is already in the destination folder.`);
  }

  /**
   * Tells the user a finished run collected nothing, when that is the whole story (issue #81).
   *
   * Reported only when EVERY attachment the note examined was left exactly where it already was, and
   * only for a run the user singled this note out for - the same reasoning every other per-note
   * report here follows, see {@link CollectAttachmentContext.isSingleNoteRun}. Any other skip reason
   * - excluded from collecting, referenced by a raw path, shared with several notes, handed to a
   * higher-priority one - leaves the two sets different sizes, and a message claiming everything is
   * already in place would then be false; each of those reasons reports itself anyway. A note holding
   * no attachment at all says nothing either: there the command found none rather than declining to
   * move one.
   *
   * @param params - The parameters.
   */
  private reportNothingCollected(params: AttachmentCollectorReportNothingCollectedParams): void {
    if (!params.context.isSingleNoteRun || params.alreadyInPlaceAttachmentPaths.size === 0 || params.alreadyInPlaceAttachmentPaths.size !== params.examinedAttachmentPaths.size) {
      return;
    }

    this.pluginNoticeComponent.showNotice(this.buildNothingToCollectNoticeMessage(params.notePath), { shouldHideOnClick: false });
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

    if (changes.length === 0) {
      return;
    }

    await applyFileChanges({
      app: this.app,
      changesProvider: changes,
      pathOrFile: params.note,
      pluginNoticeComponent: this.pluginNoticeComponent,
      resourceLockComponent: this.resourceLockComponent
    });
    params.abortSignal.throwIfAborted();
  }

  /**
   * Opt-in safety net for issue #46: when enabled, scans every note's raw text for a non-indexed
   * reference to the attachment (e.g. another plugin's custom syntax or raw HTML). If one is found,
   * warns, shows a notice, and returns `true` so the caller skips relocating the attachment - erring
   * toward NOT moving, since a false positive merely leaves it un-collected while a false negative
   * could relocate a still-used attachment and lose it. Does NOT rewrite the non-standard reference.
   */
  /**
   * Shows the notice that stays up while a note is being collected.
   *
   * An automatic run shows none. It fires on every save of the note, so a permanent notice would flash on each
   * one, and the user did not ask for this run and is not waiting for it.
   *
   * @param context - The run's context.
   * @param notePath - The note being collected.
   * @returns What hides the notice again.
   */
  private showCollectingNotice(context: CollectAttachmentContext, notePath: string): () => void {
    if (context.isAutomaticRun) {
      return noop;
    }

    const notice = this.pluginNoticeComponent.showNotice(t(($) => $.notice.collectingAttachments, { noteFilePath: notePath }), {
      isPermanent: true
    });
    return () => {
      notice.hide();
    };
  }

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
