import type { TFolder } from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';

import { FolderCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/folder-command-handler';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { Plugin } from '../plugin.ts';

import { collectAttachmentsInAbstractFiles } from '../attachment-collector.ts';

interface CollectAttachmentsInCurrentFolderCommandHandlerConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly consoleDebugComponent: ConsoleDebugComponent;
  readonly plugin: Plugin;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class CollectAttachmentsInCurrentFolderCommandHandler extends FolderCommandHandler {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly consoleDebugComponent: ConsoleDebugComponent;
  private readonly plugin: Plugin;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CollectAttachmentsInCurrentFolderCommandHandlerConstructorParams) {
    super({
      icon: 'download',
      id: 'collect-attachments-in-current-folder',
      name: t(($) => $.commands.collectAttachmentsCurrentFolder)
    });

    this.abortSignalComponent = params.abortSignalComponent;
    this.plugin = params.plugin;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.consoleDebugComponent = params.consoleDebugComponent;
  }

  protected override executeFolder(folder: TFolder): void {
    collectAttachmentsInAbstractFiles(this.plugin, [folder], this.abortSignalComponent, this.pluginSettingsComponent, this.consoleDebugComponent);
  }
}
