import type {
  App,
  TAbstractFile
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';
import type { Promisable } from 'type-fest';

import { noopAsync } from 'obsidian-dev-utils/function';
import { AbstractFileCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/abstract-file-command-handler';
import {
  isFile,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { collectAttachmentsInAbstractFiles } from '../attachment-collector.ts';

interface CollectAttachmentsInFileCommandHandlerConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly app: App;
  readonly consoleDebugComponent: ConsoleDebugComponent;
  readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class CollectAttachmentsInFileCommandHandler extends AbstractFileCommandHandler {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly app: App;
  private readonly consoleDebugComponent: ConsoleDebugComponent;
  private readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CollectAttachmentsInFileCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.collectAttachmentsInFile),
      filesMenuItemName: t(($) => $.menuItems.collectAttachmentsInFiles),
      icon: 'download',
      id: 'collect-attachments-in-file',
      name: t(($) => $.commands.collectAttachmentsCurrentNote)
    });

    this.app = params.app;
    this.customAttachmentLocationComponent = params.customAttachmentLocationComponent;
    this.abortSignalComponent = params.abortSignalComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.consoleDebugComponent = params.consoleDebugComponent;
  }

  protected override canExecuteAbstractFiles(abstractFiles: TAbstractFile[]): boolean {
    if (!super.canExecute()) {
      return false;
    }

    for (const abstractFile of abstractFiles) {
      if (isFile(abstractFile) && !isNote(this.app, abstractFile)) {
        return false;
      }
    }

    return true;
  }

  protected override executeAbstractFile(abstractFile: TAbstractFile): Promisable<void> {
    return this.executeAbstractFiles([abstractFile]);
  }

  protected override executeAbstractFiles(abstractFiles: TAbstractFile[]): Promise<void> {
    collectAttachmentsInAbstractFiles(this.customAttachmentLocationComponent, abstractFiles, this.abortSignalComponent, this.pluginSettingsComponent, this.consoleDebugComponent);
    return noopAsync();
  }

  protected override shouldAddToAbstractFileMenu(): boolean {
    return true;
  }

  protected override shouldAddToAbstractFilesMenu(): boolean {
    return true;
  }
}
