import type { TAbstractFile } from 'obsidian';
import type { Promisable } from 'type-fest';

import { noopAsync } from 'obsidian-dev-utils/function';
import { AbstractFileCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/abstract-file-command-handler';
import {
  isFile,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { AttachmentCollector } from '../attachment-collector.ts';

interface CollectAttachmentsInFileCommandHandlerConstructorParams {
  readonly attachmentCollector: AttachmentCollector;
}

export class CollectAttachmentsInFileCommandHandler extends AbstractFileCommandHandler {
  private readonly attachmentCollector: AttachmentCollector;

  public constructor(params: CollectAttachmentsInFileCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.collectAttachmentsInFile),
      filesMenuItemName: t(($) => $.menuItems.collectAttachmentsInFiles),
      icon: 'download',
      id: 'collect-attachments-in-file',
      name: t(($) => $.commands.collectAttachmentsCurrentNote)
    });

    this.attachmentCollector = params.attachmentCollector;
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
    this.attachmentCollector.collectAttachmentsInAbstractFiles(abstractFiles);
    return noopAsync();
  }

  protected override shouldAddToAbstractFileMenu(): boolean {
    return true;
  }

  protected override shouldAddToAbstractFilesMenu(): boolean {
    return true;
  }
}
