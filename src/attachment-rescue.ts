/**
 * @file
 *
 * Decides where an attachment goes when the deletion of a note — or of the folder that note lives in —
 * would otherwise strand it.
 *
 * Deleting a note whose attachment another note still references does not destroy the attachment;
 * `obsidian-dev-utils` keeps it. What it cannot decide is where the survivor should live, because that
 * is this plugin's attachment-path policy. So the rename/delete handler asks, through its optional
 * `getRescuePath` hook, and everything here answers that one question: a destination path, or `null`
 * to leave the attachment exactly where it is.
 *
 * The answer must be free of side effects. The handler calls the hook TWICE for a folder deletion —
 * the owning note's own deletion re-walks its links afterwards — and performs the move itself once it
 * has the path.
 */

import type { App } from 'obsidian';
import type { GetRescuePathParams } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';

import { join } from 'obsidian-dev-utils/path';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import {
  findNotePriorityRank,
  pickHighestPriorityNotePath
} from './note-priority.ts';
import { ActionContext } from './token-evaluator-context.ts';

/**
 * Parameters for {@link pickRescueNotePath}.
 */
export interface PickRescueNotePathParams {
  /**
   * The priority list, highest priority first. Empty means the user has expressed no preference.
   */
  readonly entries: readonly string[];

  /**
   * The priority rank of a note. Lower wins.
   *
   * @param notePath - The vault-relative path of the note.
   * @returns The rank.
   */
  rank(this: void, notePath: string): number;

  /**
   * The vault-relative paths of the notes that still reference the attachment once the deletion is done.
   */
  readonly survivingNotePaths: readonly string[];
}

interface AttachmentRescuerConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

type AttachmentRescuerGetRescuePathParams = GetRescuePathParams;

/**
 * Answers the rename/delete handler's `getRescuePath` hook using this plugin's attachment-path settings.
 */
export class AttachmentRescuer {
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: AttachmentRescuerConstructorParams) {
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
   * Resolves where an attachment about to be stranded should be moved to.
   *
   * @param params - The parameters provided by the rename/delete handler.
   * @returns The destination path, or `null` to leave the attachment where it is.
   */
  public async getRescuePath(params: AttachmentRescuerGetRescuePathParams): Promise<null | string> {
    if (!this.pluginSettingsComponent.settings.shouldRescueSharedAttachments) {
      return null;
    }

    const attachmentFile = this.app.vault.getFileByPath(params.attachmentPath);
    if (!attachmentFile) {
      return null;
    }

    const notePath = pickRescueNotePath({
      entries: this.pluginSettingsComponent.settings.notePriorities,
      rank: (candidateNotePath) => this.findRank(candidateNotePath),
      survivingNotePaths: params.survivingNotePaths
    });

    if (notePath === null) {
      return null;
    }

    const attachmentFolderPath = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
      actionContext: ActionContext.DeleteNote,
      attachmentFileName: attachmentFile.name,
      attachmentFileStats: attachmentFile.stat,
      notePath,
      // Lazy on purpose: a folder pattern that reads no content must not pay for a binary read of
      // Every attachment a bulk deletion walks past.
      readAttachmentFileContent: async () => await this.app.vault.readBinary(attachmentFile)
    });

    // The attachment keeps its name. A rescue relocates a file the user never named; renaming it as
    // Well would compound one surprise with another.
    return join(attachmentFolderPath, attachmentFile.name);
  }

  private findRank(notePath: string): number {
    const noteFile = this.app.vault.getFileByPath(notePath);
    return findNotePriorityRank({
      entries: this.pluginSettingsComponent.settings.notePriorities,
      frontmatter: noteFile ? this.app.metadataCache.getFileCache(noteFile)?.frontmatter ?? null : null,
      notePath
    });
  }
}

/**
 * Picks the note whose attachment folder a stranded attachment should be moved into.
 *
 * A single surviving note wins outright, WITHOUT consulting the priority list. That list is empty by
 * default, so ranking first would mean the rescue never fired for anybody who had not filled it in —
 * and with only one note left there is nothing to rank anyway.
 *
 * Several surviving notes fall to the same {@link pickHighestPriorityNotePath} the collecting commands
 * use, which returns `null` on a tie or when nothing matched. `null` here means "leave it in place",
 * which is today's behavior and the conservative answer to an ambiguity the user has not resolved.
 *
 * @param params - The parameters for picking the note.
 * @returns The winning note's path, or `null` when there is no single winner.
 */
export function pickRescueNotePath(params: PickRescueNotePathParams): null | string {
  const [firstNotePath] = params.survivingNotePaths;
  if (firstNotePath !== undefined && params.survivingNotePaths.length === 1) {
    return firstNotePath;
  }

  if (params.entries.length === 0) {
    return null;
  }

  return pickHighestPriorityNotePath({
    notePaths: params.survivingNotePaths,
    rank: (notePath) => params.rank(notePath)
  });
}
