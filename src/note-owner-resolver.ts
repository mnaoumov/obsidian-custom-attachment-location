/**
 * @file
 *
 * Answers "which note owns this attachment?".
 *
 * The attachment folder path is a template, so it cannot be run backwards: `${prompt}` and `${random}`
 * throw away the very value the folder name was built from, and nothing stops two notes resolving to
 * the same folder. The only reliable inverse is the link graph, ranked by the note-priority list the
 * user has already configured for exactly this question.
 *
 * The unit-folder widening matters more than it looks. A folder that travels as one unit — a saved
 * web page's `_files`, an `.excalidraw` sidecar tree — usually has a single linked entry point and a
 * pile of unlinked members next to it. Asking only for the selected file's own backlinks would leave
 * every one of those members ownerless, so the whole unit is consulted instead.
 */

import type {
  App,
  TFile
} from 'obsidian';

import { Vault } from 'obsidian';
import { findAttachmentUnitFolderPath } from 'obsidian-dev-utils/obsidian/attachment-unit-folder';
import { isFile } from 'obsidian-dev-utils/obsidian/file-system';
import { getBacklinksForFileSafe } from 'obsidian-dev-utils/obsidian/metadata-cache';

import type { NoPriorityWinnerReason } from './note-priority.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import {
  findNoPriorityWinnerReason,
  findNotePriorityRank,
  pickHighestPriorityNotePath
} from './note-priority.ts';

interface NoteOwnerResolverConstructorParams {
  readonly app: App;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class NoteOwnerResolver {
  private readonly app: App;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: NoteOwnerResolverConstructorParams) {
    this.app = params.app;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
   * Collects every note that could own the attachment, sorted by path.
   *
   * @param attachmentFile - The attachment.
   * @returns The candidate notes' vault-relative paths.
   */
  public async findCandidateNotePaths(attachmentFile: TFile): Promise<string[]> {
    const notePaths = new Set<string>();
    await this.addBacklinkNotePaths(attachmentFile.path, notePaths);

    for (const siblingPath of this.findUnitFolderSiblingPaths(attachmentFile)) {
      await this.addBacklinkNotePaths(siblingPath, notePaths);
    }

    // A note can reference itself only through a link the user typed; it is never its own attachment.
    notePaths.delete(attachmentFile.path);
    return [...notePaths].sort((a, b) => a.localeCompare(b));
  }

  /**
   * Explains why the priority list named no owner, so the caller can tell the user the real reason
   * instead of only listing the notes. Meaningful once {@link pickOwnerNotePath} has returned `null`.
   *
   * @param notePaths - The candidate notes' vault-relative paths.
   * @returns Which of the three ways the list failed to settle it.
   */
  public findNoPriorityWinnerReason(notePaths: readonly string[]): NoPriorityWinnerReason {
    const entries = this.pluginSettingsComponent.settings.notePriorities;
    return findNoPriorityWinnerReason({
      entries,
      notePaths,
      rank: (notePath) => this.rankNote(entries, notePath)
    });
  }

  /**
   * Picks the note that owns an attachment several notes reference, or `null` when the priority list
   * does not settle it — no entry matched, or the best rank is shared.
   *
   * @param notePaths - The candidate notes' vault-relative paths.
   * @returns The owning note's path, or `null` when there is no single winner.
   */
  public pickOwnerNotePath(notePaths: readonly string[]): null | string {
    const entries = this.pluginSettingsComponent.settings.notePriorities;
    if (entries.length === 0) {
      return null;
    }

    return pickHighestPriorityNotePath({
      notePaths,
      rank: (notePath) => this.rankNote(entries, notePath)
    });
  }

  /**
   * Finds how highly a note ranks in the priority list.
   *
   * @param entries - The priority list, highest priority first.
   * @param notePath - The note's vault-relative path.
   * @returns The rank; infinite when the note matches nothing.
   */
  public rankNote(entries: readonly string[], notePath: string): number {
    const noteFile = this.app.vault.getFileByPath(notePath);
    return findNotePriorityRank({
      entries,
      frontmatter: noteFile ? this.app.metadataCache.getFileCache(noteFile)?.frontmatter ?? null : null,
      notePath
    });
  }

  private async addBacklinkNotePaths(path: string, notePaths: Set<string>): Promise<void> {
    const backlinks = await getBacklinksForFileSafe({
      app: this.app,
      pathOrFile: path
    });

    for (const backlinkPath of backlinks.keys()) {
      if (this.pluginSettingsComponent.isNoteEx(backlinkPath)) {
        notePaths.add(backlinkPath);
      }
    }
  }

  private findUnitFolderSiblingPaths(attachmentFile: TFile): string[] {
    const unitFolderPath = findAttachmentUnitFolderPath({
      attachmentPath: attachmentFile.path,
      checkIsAttachmentUnitFolder: (folderPath) => this.pluginSettingsComponent.settings.isAttachmentUnitFolder(folderPath)
    });

    if (unitFolderPath === null) {
      return [];
    }

    const unitFolder = this.app.vault.getFolderByPath(unitFolderPath);
    if (!unitFolder) {
      return [];
    }

    const siblingPaths: string[] = [];
    Vault.recurseChildren(unitFolder, (child) => {
      if (isFile(child) && child.path !== attachmentFile.path) {
        siblingPaths.push(child.path);
      }
    });
    return siblingPaths;
  }
}
