import { noopAsync } from 'obsidian-dev-utils/function';
import { GlobalCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/global-command-handler';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { AttachmentCollector } from '../attachment-collector.ts';

interface CollectAttachmentsEntireVaultCommandHandlerConstructorParams {
  readonly attachmentCollector: AttachmentCollector;
}

export class CollectAttachmentsEntireVaultCommandHandler extends GlobalCommandHandler {
  private readonly attachmentCollector: AttachmentCollector;

  public constructor(params: CollectAttachmentsEntireVaultCommandHandlerConstructorParams) {
    super({
      icon: 'download',
      id: 'collect-attachments-entire-vault',
      name: t(($) => $.commands.collectAttachmentsEntireVault)
    });
    this.attachmentCollector = params.attachmentCollector;
  }

  protected override async execute(): Promise<void> {
    await noopAsync();
    this.attachmentCollector.collectAttachmentsEntireVault();
  }
}
