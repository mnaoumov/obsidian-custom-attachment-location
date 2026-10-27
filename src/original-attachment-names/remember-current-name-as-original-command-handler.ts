import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { TFile } from 'obsidian';

import { FileCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/file-command-handler';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

interface RememberCurrentNameAsOriginalCommandHandlerConstructorParams {
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
 * Makes an attachment's current name the original that `{{originalAttachmentFileName}}` builds on.
 *
 * For an attachment whose true original is useless, such as `Pasted image <timestamp>.png` renamed by hand to
 * something meaningful.
 */
export class RememberCurrentNameAsOriginalCommandHandler extends FileCommandHandler {
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: RememberCurrentNameAsOriginalCommandHandlerConstructorParams) {
    super({
      fileMenuItemName: t(($) => $.menuItems.rememberCurrentNameAsOriginal),
      filesMenuItemName: t(($) => $.menuItems.rememberCurrentNamesAsOriginals),
      icon: 'bookmark-check',
      id: 'remember-current-name-as-original',
      name: t(($) => $.commands.rememberCurrentNameAsOriginal)
    });
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  protected override canExecuteFile(file: TFile): boolean {
    return !this.pluginSettingsComponent.isNoteEx(file);
  }

  protected override executeFile(file: TFile): void {
    this.executeFiles([file]);
  }

  protected override executeFiles(files: TFile[]): void {
    for (const file of files) {
      this.originalAttachmentNamesComponent.set(file.path, file.name);
    }
    this.pluginNoticeComponent.showNotice(t(($) => $.originalAttachmentNames.rememberedNotice, { count: files.length }));
  }

  protected override shouldAddToFileMenu(): boolean {
    return true;
  }

  protected override shouldAddToFilesMenu(): boolean {
    return true;
  }
}
