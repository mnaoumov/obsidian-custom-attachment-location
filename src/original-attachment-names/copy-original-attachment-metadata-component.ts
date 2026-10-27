import type {
  App,
  Menu,
  TAbstractFile
} from 'obsidian';

import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { convertAsyncToSync } from '@mnaoumov/typescript-lib/async';
import {
  Component,
  TFile
} from 'obsidian';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

interface CopyOriginalAttachmentMetadataComponentConstructorParams {
  readonly app: App;
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
Adds independent copy actions to file menus, including menus opened on resolved attachment links.
*/
export class CopyOriginalAttachmentMetadataComponent extends Component {
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
      this.addCopyActions(menu, file);
    }));
  }

  private addCopyActions(menu: Menu, file: TAbstractFile): void {
    if (!(file instanceof TFile) || this.pluginSettingsComponent.isNoteEx(file)) {
      return;
    }
    const actions = [
      { title: t(($) => $.menuItems.copyOriginalFileName), value: this.originalAttachmentNamesComponent.get(file.path) },
      { title: t(($) => $.menuItems.copyOriginalPath), value: this.originalAttachmentNamesComponent.getOriginalPath(file.path) }
    ];
    for (const { title, value } of actions) {
      menu.addItem((item) => {
        item.setTitle(title).setIcon('copy').setSection('action').setDisabled(!value).onClick(convertAsyncToSync(async () => {
          if (value) {
            // eslint-disable-next-line n/no-unsupported-features/node-builtins -- Obsidian's browser clipboard, not Node's experimental navigator.
            await window.navigator.clipboard.writeText(value);
          }
        }));
      });
    }
  }
}
