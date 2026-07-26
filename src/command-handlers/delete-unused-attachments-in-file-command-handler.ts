import type { TAbstractFile } from 'obsidian';
import type { Promisable } from 'type-fest';

import { noopAsync } from 'obsidian-dev-utils/function';
import { AbstractFileCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/abstract-file-command-handler';
import {
  isFile,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { UnusedAttachmentsRemover } from '../unused-attachments-remover.ts';

interface DeleteUnusedAttachmentsInFileCommandHandlerConstructorParams {
  readonly unusedAttachmentsRemover: UnusedAttachmentsRemover;
}

export class DeleteUnusedAttachmentsInFileCommandHandler extends AbstractFileCommandHandler {
  private readonly unusedAttachmentsRemover: UnusedAttachmentsRemover;

  public constructor(params: DeleteUnusedAttachmentsInFileCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.deleteUnusedAttachmentsInFile),
      filesMenuItemName: t(($) => $.menuItems.deleteUnusedAttachmentsInFiles),
      icon: 'trash-2',
      id: 'delete-unused-attachments-in-file',
      name: t(($) => $.commands.deleteUnusedAttachmentsCurrentNote)
    });

    this.unusedAttachmentsRemover = params.unusedAttachmentsRemover;
  }

  protected override canExecuteAbstractFiles(abstractFiles: TAbstractFile[]): boolean {
    if (!super.canExecute()) {
      return false;
    }

    for (const abstractFile of abstractFiles) {
      if (isFile(abstractFile) && !isNote(abstractFile)) {
        return false;
      }
    }

    return true;
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
