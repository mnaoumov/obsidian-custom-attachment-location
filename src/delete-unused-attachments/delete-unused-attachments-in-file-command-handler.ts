import type { BulkOperationCommitComponent } from '@mnaoumov/obsidian-lib/components/bulk-operation-commit-component';
import type { TAbstractFile } from 'obsidian';
import type { Promisable } from 'type-fest';

import { AbstractFileCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/abstract-file-command-handler';
import { isFile } from '@mnaoumov/obsidian-lib/file-system';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { UnusedAttachmentsRemover } from './unused-attachments-remover.ts';

import { buildBulkOperationSummary } from '../bulk-operations/bulk-operation-summary.ts';

interface DeleteUnusedAttachmentsInFileCommandHandlerConstructorParams {
  readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly unusedAttachmentsRemover: UnusedAttachmentsRemover;
}

export class DeleteUnusedAttachmentsInFileCommandHandler extends AbstractFileCommandHandler {
  private readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
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

    this.bulkOperationCommitComponent = params.bulkOperationCommitComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.unusedAttachmentsRemover = params.unusedAttachmentsRemover;
  }

  /**
   * Whether the command may run for one file or folder.
   *
   * `isNoteEx`, not the plain extension-based `isNote` its collect twin keeps on purpose, for a reason of
   * the sweep's own: the walk in `unused-attachments-remover.ts` never scans a file listed in
   * `treatAsAttachmentExtensions` as a note — a drawing is an attachment of the note that embeds it, and
   * judging the folder its path resolves to as if the drawing owned it would put that folder's files up for
   * trashing. Offering the command on such a file would offer a command that does nothing.
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

  protected override async executeAbstractFiles(abstractFiles: TAbstractFile[]): Promise<void> {
    await this.bulkOperationCommitComponent.runBulkOperation({
      operation: () => this.unusedAttachmentsRemover.deleteUnusedAttachmentsInAbstractFiles(abstractFiles),
      summary: buildBulkOperationSummary('Delete unused attachments', abstractFiles)
    });
  }

  protected override shouldAddToAbstractFileMenu(): boolean {
    return true;
  }

  protected override shouldAddToAbstractFilesMenu(): boolean {
    return true;
  }
}
