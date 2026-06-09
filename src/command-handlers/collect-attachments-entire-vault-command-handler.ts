import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';

import { noopAsync } from 'obsidian-dev-utils/function';
import { GlobalCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/global-command-handler';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { Plugin } from '../plugin.ts';

import { collectAttachmentsEntireVault } from '../attachment-collector.ts';

interface CollectAttachmentsEntireVaultCommandHandlerConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly consoleDebugComponent: ConsoleDebugComponent;
  readonly plugin: Plugin;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class CollectAttachmentsEntireVaultCommandHandler extends GlobalCommandHandler {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly consoleDebugComponent: ConsoleDebugComponent;
  private readonly plugin: Plugin;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CollectAttachmentsEntireVaultCommandHandlerConstructorParams) {
    super({
      icon: 'download',
      id: 'collect-attachments-entire-vault',
      name: t(($) => $.commands.collectAttachmentsEntireVault)
    });
    this.abortSignalComponent = params.abortSignalComponent;
    this.plugin = params.plugin;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.consoleDebugComponent = params.consoleDebugComponent;
  }

  protected override async execute(): Promise<void> {
    await noopAsync();
    collectAttachmentsEntireVault(this.plugin, this.abortSignalComponent, this.pluginSettingsComponent, this.consoleDebugComponent);
  }
}
