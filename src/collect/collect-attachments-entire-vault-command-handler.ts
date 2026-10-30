import type { BulkOperationCommitComponent } from '@mnaoumov/obsidian-lib/components/bulk-operation-commit-component';

import { GlobalCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/global-command-handler';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';

import type { AttachmentCollector } from './attachment-collector.ts';

import { buildBulkOperationSummary } from '../bulk-operations/bulk-operation-summary.ts';

interface CollectAttachmentsEntireVaultCommandHandlerConstructorParams {
  readonly attachmentCollector: AttachmentCollector;
  readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
}

export class CollectAttachmentsEntireVaultCommandHandler extends GlobalCommandHandler {
  private readonly attachmentCollector: AttachmentCollector;
  private readonly bulkOperationCommitComponent: BulkOperationCommitComponent;

  public constructor(params: CollectAttachmentsEntireVaultCommandHandlerConstructorParams) {
    super({
      icon: 'download',
      id: 'collect-attachments-entire-vault',
      name: t(($) => $.commands.collectAttachmentsEntireVault)
    });
    this.attachmentCollector = params.attachmentCollector;
    this.bulkOperationCommitComponent = params.bulkOperationCommitComponent;
  }

  protected override async execute(): Promise<void> {
    await this.bulkOperationCommitComponent.runBulkOperation({
      operation: () => this.attachmentCollector.collectAttachmentsEntireVault(),
      summary: buildBulkOperationSummary('Collect attachments')
    });
  }
}
