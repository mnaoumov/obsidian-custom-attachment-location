import type {
  App,
  Menu,
  TAbstractFile
} from 'obsidian';

import { ComponentEx } from '@mnaoumov/obsidian-lib/components/component-ex';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { convertAsyncToSync } from '@mnaoumov/typescript-lib/async';
import { TFile } from 'obsidian';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

interface CopyOriginalAttachmentMetadataComponentConstructorParams {
  readonly app: App;
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
Adds the copy-original-file-name action to file menus, including menus opened on resolved attachment links.
*/
export class CopyOriginalAttachmentMetadataComponent extends ComponentEx {
  private readonly app: App;
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CopyOriginalAttachmentMetadataComponentConstructorParams) {
    super();
    this.app = params.app;
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public override onload(): void {
    this.registerEvent(this.app.workspace.on('file-menu', (menu, file) => {
      this.addCopyAction(menu, file);
    }));
  }

  private addCopyAction(menu: Menu, file: TAbstractFile): void {
    if (!(file instanceof TFile) || this.pluginSettingsComponent.isNoteEx(file)) {
      return;
    }
    const value = this.originalAttachmentNamesComponent.get(file.path);
    menu.addItem((item) => {
      item.setTitle(t(($) => $.menuItems.copyOriginalFileName)).setIcon('copy').setSection('action').setDisabled(!value).onClick(convertAsyncToSync(async () => {
        if (value) {
          // eslint-disable-next-line n/no-unsupported-features/node-builtins -- Obsidian's browser clipboard, not Node's experimental navigator.
          await window.navigator.clipboard.writeText(value);
        }
      }));
    });
  }
}
