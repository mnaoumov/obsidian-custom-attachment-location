import type {
  App,
  TFile
} from 'obsidian';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';

import { FileCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/file-command-handler';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { selectItem } from 'obsidian-dev-utils/obsidian/modals/select-item';

import type { NoteOwnerResolver } from '../note-owner-resolver.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME } from '../advanced-rename-and-delete-handler.ts';

interface GoToOwningNoteCommandHandlerConstructorParams {
  readonly app: App;
  readonly noteOwnerResolver: NoteOwnerResolver;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
 * Opens the note that owns the selected attachment.
 *
 * The reverse of {@link GoToAttachmentFolderCommandHandler}, but not its mirror image: the attachment
 * folder template is not invertible, so the owner comes from the link graph rather than from the path.
 */
export class GoToOwningNoteCommandHandler extends FileCommandHandler {
  private readonly app: App;
  private readonly noteOwnerResolver: NoteOwnerResolver;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: GoToOwningNoteCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.goToOwningNote),
      icon: 'file-symlink',
      id: 'go-to-owning-note',
      name: t(($) => $.commands.goToOwningNote)
    });

    this.app = params.app;
    this.noteOwnerResolver = params.noteOwnerResolver;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  protected override canExecuteFile(file: TFile): boolean {
    return !this.pluginSettingsComponent.isNoteEx(file);
  }

  protected override async executeFile(file: TFile): Promise<void> {
    const candidateNotePaths = await this.noteOwnerResolver.findCandidateNotePaths(file);

    if (candidateNotePaths.length === 0) {
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.noOwningNote, { attachmentPath: file.path }));
      return;
    }

    const notePath = candidateNotePaths.length === 1 ? candidateNotePaths[0] : await this.pickNotePath(file, candidateNotePaths);
    if (!notePath) {
      return;
    }

    const noteFile = this.app.vault.getFileByPath(notePath);
    if (!noteFile) {
      return;
    }

    await this.app.workspace.getLeaf(false).openFile(noteFile);
  }

  protected override shouldAddToFileMenu(): boolean {
    return true;
  }

  /**
   * Asks the user which note owns the attachment, but only once the priority list has failed to say.
   * The placeholder carries the reason it failed, so the user learns whether the list is empty, did not
   * match, or tied, rather than only that they are being asked.
   *
   * Only the notes tying for the best rank are offered: the list has already ruled the others out, so
   * offering one would invite an answer the plugin itself would not have given (issue #74). Both the
   * decision and the reason are still taken over every candidate.
   */
  private async pickNotePath(attachmentFile: TFile, candidateNotePaths: string[]): Promise<null | string> {
    const ownerNotePath = this.noteOwnerResolver.pickOwnerNotePath(candidateNotePaths);
    if (ownerNotePath) {
      return ownerNotePath;
    }

    const reason = this.noteOwnerResolver.findNoPriorityWinnerReason(candidateNotePaths);
    return await selectItem({
      app: this.app,
      items: this.noteOwnerResolver.filterTopRankNotePaths(candidateNotePaths),
      itemTextFunction: (notePath) => notePath,
      placeholder: `${t(($) => $.goToOwningNote.selectPlaceholder, { attachmentPath: attachmentFile.path })} ${
        t(($) => $.goToOwningNote.noPriorityWinnerReason[reason], {
          // Qualified with the owning plugin since 12.0.0 — see the same call in the collect modal.
          settingName: `${ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME} → ${t(($) => $.pluginSettingsTab.notePriorities.name)}`
        })
      }`
    });
  }
}
