import type { TFolder } from 'obsidian';

import { FolderCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/folder-command-handler';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';

import type { AttachmentCollector } from './attachment-collector.ts';

interface CollectAttachmentsInCurrentFolderCommandHandlerConstructorParams {
  readonly attachmentCollector: AttachmentCollector;
}

export class CollectAttachmentsInCurrentFolderCommandHandler extends FolderCommandHandler {
  private readonly attachmentCollector: AttachmentCollector;

  public constructor(params: CollectAttachmentsInCurrentFolderCommandHandlerConstructorParams) {
    super({
      icon: 'download',
      id: 'collect-attachments-in-current-folder',
      name: t(($) => $.commands.collectAttachmentsCurrentFolder)
    });

    this.attachmentCollector = params.attachmentCollector;
  }

  protected override executeFolder(folder: TFolder): void {
    this.attachmentCollector.collectAttachmentsInAbstractFiles([folder]);
  }
}
