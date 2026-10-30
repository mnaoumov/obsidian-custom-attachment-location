import type { BulkOperationCommitComponent } from '@mnaoumov/obsidian-lib/components/bulk-operation-commit-component';

import { GlobalCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/global-command-handler';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';

import type { UnusedAttachmentsRemover } from './unused-attachments-remover.ts';

import { buildBulkOperationSummary } from '../bulk-operations/bulk-operation-summary.ts';

interface DeleteUnusedAttachmentsEntireVaultCommandHandlerConstructorParams {
  readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
  readonly unusedAttachmentsRemover: UnusedAttachmentsRemover;
}

/**
 * A command of its own rather than a scope prompt on the existing one.
 *
 * `Delete unused attachments in current note` keeps meaning exactly what it has always meant, so a
 * hotkey or a muscle-memory palette entry can never turn into a whole-vault deletion because the
 * command grew an option.
 */
export class DeleteUnusedAttachmentsEntireVaultCommandHandler extends GlobalCommandHandler {
  private readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
  private readonly unusedAttachmentsRemover: UnusedAttachmentsRemover;

  public constructor(params: DeleteUnusedAttachmentsEntireVaultCommandHandlerConstructorParams) {
    super({
      icon: 'trash-2',
      id: 'delete-unused-attachments-entire-vault',
      name: t(($) => $.commands.deleteUnusedAttachmentsEntireVault)
    });
    this.bulkOperationCommitComponent = params.bulkOperationCommitComponent;
    this.unusedAttachmentsRemover = params.unusedAttachmentsRemover;
  }

  protected override async execute(): Promise<void> {
    await this.bulkOperationCommitComponent.runBulkOperation({
      operation: () => this.unusedAttachmentsRemover.deleteUnusedAttachmentsEntireVault(),
      summary: buildBulkOperationSummary('Delete unused attachments')
    });
  }
}
