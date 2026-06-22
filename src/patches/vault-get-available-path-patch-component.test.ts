import type { Vault as VaultOriginal } from 'obsidian';

import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { PluginSettings } from '../plugin-settings.ts';
import { VaultGetAvailablePathPatchComponent } from './vault-get-available-path-patch-component.ts';

interface VaultWithGetAvailablePath {
  getAvailablePath(attachmentFileName: string, attachmentExtension: string): string;
}

describe('VaultGetAvailablePathPatchComponent', () => {
  let app: App;
  let vault: VaultOriginal;
  let settings: PluginSettings;
  let pluginSettingsComponent: PluginSettingsComponent;

  function setup(files: Record<string, string>): void {
    app = App.createConfigured__({ files });
    vault = app.vault.asOriginalType2__();
    settings = new PluginSettings();
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      settings
    });
  }

  beforeEach(() => {
    setup({});
  });

  function createComponent(): VaultGetAvailablePathPatchComponent {
    return new VaultGetAvailablePathPatchComponent({
      app: app.asOriginalType__(),
      pluginSettingsComponent,
      vault
    });
  }

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should return the base name when no file with that path exists', () => {
    const component = createComponent();
    component.load();

    const result = strictProxy<VaultWithGetAvailablePath>(vault).getAvailablePath('note', 'png');

    expect(result).toBe('note.png');
  });

  it('should append a suffix using the duplicate name separator when paths collide', () => {
    setup({
      'note.png': '',
      'note 1.png': ''
    });
    const component = createComponent();
    component.load();

    const result = strictProxy<VaultWithGetAvailablePath>(vault).getAvailablePath('note', 'png');

    expect(result).toBe('note 2.png');
  });

  it('should honour a custom duplicate name separator', () => {
    setup({
      'note.png': ''
    });
    settings.duplicateNameSeparator = '-';
    const component = createComponent();
    component.load();

    const result = strictProxy<VaultWithGetAvailablePath>(vault).getAvailablePath('note', 'png');

    expect(result).toBe('note-1.png');
  });
});
