import type { BulkOperationCommitComponent } from '@mnaoumov/obsidian-lib/components/bulk-operation-commit-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { App } from 'obsidian';

import { GlobalCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/global-command-handler';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { assertNever } from '@mnaoumov/typescript-lib/type-guards';

import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

import {
  PruneOriginalAttachmentNamesChoice,
  showPruneOriginalAttachmentNamesModal
} from './prune-original-attachment-names-modal.ts';

interface PruneOriginalAttachmentNamesCommandHandlerConstructorParams {
  readonly app: App;
  readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
}

/**
 * Removes the remembered original names whose file no longer exists, or, on request, every one of them.
 */
export class PruneOriginalAttachmentNamesCommandHandler extends GlobalCommandHandler {
  private readonly app: App;
  private readonly bulkOperationCommitComponent: BulkOperationCommitComponent;
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;

  public constructor(params: PruneOriginalAttachmentNamesCommandHandlerConstructorParams) {
    super({
      icon: 'eraser',
      id: 'prune-original-attachment-names',
      name: t(($) => $.commands.pruneOriginalAttachmentNames)
    });
    this.app = params.app;
    this.bulkOperationCommitComponent = params.bulkOperationCommitComponent;
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
  }

  protected override async execute(): Promise<void> {
    const choice = await showPruneOriginalAttachmentNamesModal({
      app: this.app,
      originalAttachmentNamesComponent: this.originalAttachmentNamesComponent
    });

    switch (choice) {
      case PruneOriginalAttachmentNamesChoice.Cancel: {
        return;
      }
      case PruneOriginalAttachmentNamesChoice.ForgetAll: {
        const count = await this.runAndPublish('Forget all original attachment names', () => this.originalAttachmentNamesComponent.forgetAll());
        this.pluginNoticeComponent.showNotice(t(($) => $.originalAttachmentNames.forgotAllNotice, { count }));
        return;
      }
      case PruneOriginalAttachmentNamesChoice.Prune: {
        const count = await this.runAndPublish('Prune original attachment names', () => this.originalAttachmentNamesComponent.prune().length);
        this.pluginNoticeComponent.showNotice(t(($) => $.originalAttachmentNames.prunedNotice, { count }));
        return;
      }
      default: {
        assertNever(choice);
      }
    }
  }

  /**
   * Runs one change to the store as a bulk operation, publishing it before the operation ends.
   *
   * The store writes its observations into vault files on a debounce, so without the flush its commit could hold
   * nothing and the files would land in whatever commit came next. The dialog stays outside: a bulk operation
   * covers only what changes the vault.
   *
   * @param summary - The commit summary.
   * @param change - The change; returns how many records it touched.
   * @returns How many records the change touched.
   */
  private async runAndPublish(summary: string, change: () => number): Promise<number> {
    return await this.bulkOperationCommitComponent.runBulkOperation({
      operation: async () => {
        const count = change();
        await this.originalAttachmentNamesComponent.flush();
        return count;
      },
      summary
    });
  }
}
