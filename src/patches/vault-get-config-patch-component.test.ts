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

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';

import { VaultGetConfigPatchComponent } from './vault-get-config-patch-component.ts';

interface VaultWithGetConfig {
  getConfig(name: string): unknown;
}

describe('VaultGetConfigPatchComponent', () => {
  let vault: VaultOriginal;
  let customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  let currentAttachmentFolderPath: null | string;
  let getConfigMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    const app = App.createConfigured__();
    vault = app.vault.asOriginalType2__();
    currentAttachmentFolderPath = '/custom/attachments';
    getConfigMock = vi.fn().mockReturnValue('original-value');
    Object.defineProperty(vault, 'getConfig', {
      configurable: true,
      value: getConfigMock,
      writable: true
    });
    customAttachmentLocationComponent = strictProxy<CustomAttachmentLocationComponent>({
      get currentAttachmentFolderPath(): null | string {
        return currentAttachmentFolderPath;
      }
    });
  });

  function createComponent(): VaultGetConfigPatchComponent {
    return new VaultGetConfigPatchComponent({
      customAttachmentLocationComponent,
      vault
    });
  }

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should override the attachment folder path when configured', () => {
    const component = createComponent();
    component.load();

    const result = strictProxy<VaultWithGetConfig>(vault).getConfig('attachmentFolderPath');

    expect(result).toBe('/custom/attachments');
    expect(getConfigMock).not.toHaveBeenCalled();
  });

  it('should fall back when the requested config name is not the attachment folder path', () => {
    const component = createComponent();
    component.load();

    const result = strictProxy<VaultWithGetConfig>(vault).getConfig('someOtherSetting');

    expect(result).toBe('original-value');
    expect(getConfigMock).toHaveBeenCalledWith('someOtherSetting');
  });

  it('should fall back when no current attachment folder path is set', () => {
    currentAttachmentFolderPath = null;
    const component = createComponent();
    component.load();

    const result = strictProxy<VaultWithGetConfig>(vault).getConfig('attachmentFolderPath');

    expect(result).toBe('original-value');
    expect(getConfigMock).toHaveBeenCalledWith('attachmentFolderPath');
  });
});
