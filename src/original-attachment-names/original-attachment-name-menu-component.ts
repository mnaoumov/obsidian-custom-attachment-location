import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type {
  App,
  Menu,
  TAbstractFile
} from 'obsidian';

import { ComponentEx } from '@mnaoumov/obsidian-lib/components/component-ex';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { convertAsyncToSync } from '@mnaoumov/typescript-lib/async';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

import { getOriginalAttachmentNameTarget } from './original-attachment-name-target.ts';
import { showOriginalFileNameModal } from './original-file-name-modal.ts';

interface OriginalAttachmentNameMenuComponentConstructorParams {
  readonly app: App;
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
Adds the `Show original file name` action to file menus, including menus opened on resolved attachment links.

The action opens a dialog showing the stored name, with a copy button, rather than copying it unseen. With no stored
name it stays visible but disabled.
*/
export class OriginalAttachmentNameMenuComponent extends ComponentEx {
  private readonly app: App;
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: OriginalAttachmentNameMenuComponentConstructorParams) {
    super();
    this.app = params.app;
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public override onload(): void {
    this.registerEvent(this.app.workspace.on('file-menu', (menu, file) => {
      this.addShowAction(menu, file);
    }));
  }

  private addShowAction(menu: Menu, file: TAbstractFile): void {
    const target = getOriginalAttachmentNameTarget({
      file,
      originalAttachmentNamesComponent: this.originalAttachmentNamesComponent,
      pluginSettingsComponent: this.pluginSettingsComponent
    });
    if (!target) {
      return;
    }
    const { attachment, originalFileName } = target;
    menu.addItem((item) => {
      item.setTitle(t(($) => $.menuItems.showOriginalFileName)).setIcon('file-search').setSection('action').setDisabled(!originalFileName).onClick(
        convertAsyncToSync(async () => {
          if (!originalFileName) {
            return;
          }
          await showOriginalFileNameModal({
            app: this.app,
            attachmentPath: attachment.path,
            originalFileName,
            pluginNoticeComponent: this.pluginNoticeComponent
          });
        })
      );
    });
  }
}
