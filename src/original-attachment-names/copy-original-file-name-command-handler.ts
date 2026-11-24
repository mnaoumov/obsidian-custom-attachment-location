import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { App } from 'obsidian';

import { GlobalCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/global-command-handler';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

import { getActiveOriginalAttachmentNameTarget } from './original-attachment-name-target.ts';
import { copyOriginalFileName } from './original-file-name-modal.ts';

interface CopyOriginalFileNameCommandHandlerConstructorParams {
  readonly app: App;
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
 * Copies the name an attachment arrived with straight to the clipboard, so the user can bind a hotkey to it.
 *
 * The attachment is the open one, or the one a link under the editor's cursor resolves to. The command is available
 * only while that attachment has a stored name, as the `Show original file name` menu item is enabled only then.
 */
export class CopyOriginalFileNameCommandHandler extends GlobalCommandHandler {
  private readonly app: App;
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CopyOriginalFileNameCommandHandlerConstructorParams) {
    super({
      icon: 'copy',
      id: 'copy-original-file-name',
      name: t(($) => $.commands.copyOriginalFileName)
    });
    this.app = params.app;
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  protected override canExecute(): boolean {
    return this.getOriginalFileName() !== null;
  }

  protected override async execute(): Promise<void> {
    const originalFileName = this.getOriginalFileName();
    if (originalFileName === null) {
      return;
    }
    await copyOriginalFileName({
      originalFileName,
      pluginNoticeComponent: this.pluginNoticeComponent
    });
  }

  private getOriginalFileName(): null | string {
    return getActiveOriginalAttachmentNameTarget({
      app: this.app,
      originalAttachmentNamesComponent: this.originalAttachmentNamesComponent,
      pluginSettingsComponent: this.pluginSettingsComponent
    })?.originalFileName ?? null;
  }
}
