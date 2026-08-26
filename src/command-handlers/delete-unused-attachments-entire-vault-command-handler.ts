import { noopAsync } from 'obsidian-dev-utils/function';
import { GlobalCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/global-command-handler';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { UnusedAttachmentsRemover } from '../unused-attachments-remover.ts';

interface DeleteUnusedAttachmentsEntireVaultCommandHandlerConstructorParams {
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
  private readonly unusedAttachmentsRemover: UnusedAttachmentsRemover;

  public constructor(params: DeleteUnusedAttachmentsEntireVaultCommandHandlerConstructorParams) {
    super({
      icon: 'trash-2',
      id: 'delete-unused-attachments-entire-vault',
      name: t(($) => $.commands.deleteUnusedAttachmentsEntireVault)
    });
    this.unusedAttachmentsRemover = params.unusedAttachmentsRemover;
  }

  protected override async execute(): Promise<void> {
    await noopAsync();
    this.unusedAttachmentsRemover.deleteUnusedAttachmentsEntireVault();
  }
}
