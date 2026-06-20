import type {
  App,
  Vault
} from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import { getAbstractFileOrNull } from 'obsidian-dev-utils/obsidian/file-system';
import { makeFileName } from 'obsidian-dev-utils/path';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

interface VaultGetAvailablePathPatchComponentConstructorParams {
  readonly app: App;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly vault: Vault;
}

export class VaultGetAvailablePathPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly vault: Vault;

  public constructor(params: VaultGetAvailablePathPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.vault = params.vault;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'getAvailablePath',
      obj: this.vault,
      patchHandler: ({
        originalArgs: [attachmentFileName, attachmentExtension]
      }) => {
        let suffixNum = 0;

        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Easiest infinite loop.
        while (true) {
          const path = makeFileName(
            suffixNum === 0 ? attachmentFileName : `${attachmentFileName}${this.pluginSettingsComponent.settings.duplicateNameSeparator}${String(suffixNum)}`,
            attachmentExtension
          );

          if (!getAbstractFileOrNull(this.app, path, true)) {
            return path;
          }

          suffixNum++;
        }
      }
    });
  }
}
