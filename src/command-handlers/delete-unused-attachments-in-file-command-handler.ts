import type { TAbstractFile } from 'obsidian';
import type { Promisable } from 'type-fest';

import { noopAsync } from 'obsidian-dev-utils/function';
import { AbstractFileCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/abstract-file-command-handler';
import { isFile } from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { UnusedAttachmentsRemover } from '../unused-attachments-remover.ts';

interface DeleteUnusedAttachmentsInFileCommandHandlerConstructorParams {
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly unusedAttachmentsRemover: UnusedAttachmentsRemover;
}

export class DeleteUnusedAttachmentsInFileCommandHandler extends AbstractFileCommandHandler {
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly unusedAttachmentsRemover: UnusedAttachmentsRemover;

  public constructor(params: DeleteUnusedAttachmentsInFileCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.deleteUnusedAttachmentsInFile),
      filesMenuItemName: t(($) => $.menuItems.deleteUnusedAttachmentsInFiles),
      icon: 'trash-2',
      id: 'delete-unused-attachments-in-file',
      name: t(($) => $.commands.deleteUnusedAttachmentsCurrentNote)
    });

    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.unusedAttachmentsRemover = params.unusedAttachmentsRemover;
  }

  /**
   * Whether the command may run for one file or folder.
   *
   * `isNoteEx`, not the plain extension-based `isNote` its collect twin keeps on purpose, for a reason of
   * the sweep's own: it learns what a note references from the metadata cache, and a drawing keeps its
   * references where the cache does not carry them, so scanning one yields an EMPTY reference set and
   * every file in the folder it owns becomes a candidate to trash. The walk in
   * `unused-attachments-remover.ts` skips such a file for that reason, so offering the command on one
   * would offer a command that does nothing.
   *
   * The PER-FILE predicate for the same reason its twin in
   * `collect-attachments-in-file-command-handler.ts` is: it is the one the palette, the single-file menu
   * and the multi-select menu all reach, where a `canExecuteAbstractFiles` override answers only the last.
   *
   * @param abstractFile - The file or folder.
   * @returns Whether the command may run for it. A folder always may — the walk inside it filters.
   */
  protected override canExecuteAbstractFile(abstractFile: TAbstractFile): boolean {
    return !isFile(abstractFile) || this.pluginSettingsComponent.isNoteEx(abstractFile);
  }

  protected override executeAbstractFile(abstractFile: TAbstractFile): Promisable<void> {
    return this.executeAbstractFiles([abstractFile]);
  }

  protected override executeAbstractFiles(abstractFiles: TAbstractFile[]): Promise<void> {
    this.unusedAttachmentsRemover.deleteUnusedAttachmentsInAbstractFiles(abstractFiles);
    return noopAsync();
  }

  protected override shouldAddToAbstractFileMenu(): boolean {
    return true;
  }

  protected override shouldAddToAbstractFilesMenu(): boolean {
    return true;
  }
}
