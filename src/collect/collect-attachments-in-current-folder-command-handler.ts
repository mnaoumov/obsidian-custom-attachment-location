import type { BulkOperationCommitComponent } from '@mnaoumov/obsidian-lib/components/bulk-operation-commit-component';
import type { TFolder } from 'obsidian';

import { FolderCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/folder-command-handler';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';

import type { AttachmentCollector } from './attachment-collector.ts';

import { buildBulkOperationSummary } from '../bulk-operations/bulk-operation-summary.ts';

interface CollectAttachmentsInCurrentFolderCommandHandlerConstructorParams {
  readonly attachmentCollector: AttachmentCollector;
  readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
}

export class CollectAttachmentsInCurrentFolderCommandHandler extends FolderCommandHandler {
  private readonly attachmentCollector: AttachmentCollector;
  private readonly bulkOperationCommitComponent: BulkOperationCommitComponent;

  public constructor(params: CollectAttachmentsInCurrentFolderCommandHandlerConstructorParams) {
    super({
      icon: 'download',
      id: 'collect-attachments-in-current-folder',
      name: t(($) => $.commands.collectAttachmentsCurrentFolder)
    });

    this.attachmentCollector = params.attachmentCollector;
    this.bulkOperationCommitComponent = params.bulkOperationCommitComponent;
  }

  protected override async executeFolder(folder: TFolder): Promise<void> {
    await this.bulkOperationCommitComponent.runBulkOperation({
      operation: () => this.attachmentCollector.collectAttachmentsInAbstractFilesAndWait([folder]),
      summary: buildBulkOperationSummary('Collect attachments', [folder])
    });
  }
}
