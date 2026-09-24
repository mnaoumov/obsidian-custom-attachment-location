import type { TAbstractFile } from 'obsidian';
import type { Promisable } from 'type-fest';

import { noopAsync } from 'obsidian-dev-utils/function';
import { AbstractFileCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/abstract-file-command-handler';
import { isFile } from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { AttachmentCollector } from '../attachment-collector.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

interface CollectAttachmentsInFileCommandHandlerConstructorParams {
  readonly attachmentCollector: AttachmentCollector;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class CollectAttachmentsInFileCommandHandler extends AbstractFileCommandHandler {
  private readonly attachmentCollector: AttachmentCollector;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CollectAttachmentsInFileCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.collectAttachmentsInFile),
      filesMenuItemName: t(($) => $.menuItems.collectAttachmentsInFiles),
      icon: 'download',
      id: 'collect-attachments-in-file',
      name: t(($) => $.commands.collectAttachmentsCurrentNote)
    });

    this.attachmentCollector = params.attachmentCollector;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
   * Whether the command may run for one file or folder.
   *
   * `isNoteEx`, not the plain extension-based `isNote`: the collector's walk skips a file listed in
   * `treatAsAttachmentExtensions` (issue #151), so offering the command on a drawing would offer one that
   * silently does nothing.
   *
   * This is the PER-FILE predicate, and it is the one all three surfaces reach: the base routes the
   * command palette (`canExecute`), the single-file menu and — by composing this over every entry — the
   * multi-select menu through it. A `canExecuteAbstractFiles` override was doing the work for the last of
   * those alone, so the palette and the file menu offered the command on a drawing however the predicate
   * answered. It also opened with `super.canExecute()`, which tests the ACTIVE file: a condition that has
   * nothing to do with a menu built from the files the user clicked.
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
