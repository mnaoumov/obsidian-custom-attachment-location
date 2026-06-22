import type { Vault as VaultOriginal } from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';

import { VaultGetAvailablePathForAttachmentsPatchComponent } from './vault-get-available-path-for-attachments-patch-component.ts';

interface PatchedMethodWithExtended {
  extended(): Promise<string>;
}

describe('VaultGetAvailablePathForAttachmentsPatchComponent', () => {
  let vault: VaultOriginal;
  let attachmentPathManager: AttachmentPathManager;
  let originalResult: string;

  beforeEach(() => {
    const app = App.createConfigured__();
    vault = app.vault.asOriginalType2__();
    originalResult = '/original/attachment/path';
    Object.defineProperty(vault, 'getAvailablePathForAttachments', {
      configurable: true,
      value: vi.fn().mockResolvedValue(originalResult),
      writable: true
    });
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getAvailablePathForAttachments: vi.fn().mockResolvedValue('/extended/attachment/path')
    });
  });

  function createComponent(): VaultGetAvailablePathForAttachmentsPatchComponent {
    return new VaultGetAvailablePathForAttachmentsPatchComponent({
      attachmentPathManager,
      vault
    });
  }

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should delegate the patched method to the original implementation', async () => {
    const component = createComponent();
    component.load();

    const result = await vault.getAvailablePathForAttachments('attachment', 'png', null);

    expect(result).toBe(originalResult);
  });

  it('should attach an extended method bound to the attachment path manager', async () => {
    const component = createComponent();
    component.load();

    const patchedMethod = castTo<PatchedMethodWithExtended>(vault.getAvailablePathForAttachments);
    const result = await patchedMethod.extended();

    expect(result).toBe('/extended/attachment/path');
    expect(vi.mocked(attachmentPathManager.getAvailablePathForAttachments)).toHaveBeenCalledTimes(1);
  });
});
