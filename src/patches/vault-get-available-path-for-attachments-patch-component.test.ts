import type { Vault as VaultOriginal } from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { AttachmentPathContext } from 'obsidian-dev-utils/obsidian/attachment-path';
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
  let originalMethod: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    const app = App.createConfigured__();
    vault = app.vault.asOriginalType2__();
    originalMethod = vi.fn().mockResolvedValue('/original/attachment/path');
    Object.defineProperty(vault, 'getAvailablePathForAttachments', {
      configurable: true,
      value: originalMethod,
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

  it('should delegate a dry resolution to the manager without creating the attachment folder', async () => {
    const component = createComponent();
    component.load();

    const result = await vault.getAvailablePathForAttachments('attachment', 'png', null);

    /*
     * The patched base method resolves the path through the plugin (issue #26): it must NOT fall back
     * to core (whose implementation eagerly creates the attachment folder).
     */
    expect(result).toBe('/extended/attachment/path');
    expect(originalMethod).not.toHaveBeenCalled();
    expect(vi.mocked(attachmentPathManager.getAvailablePathForAttachments)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(attachmentPathManager.getAvailablePathForAttachments)).toHaveBeenCalledWith({
      attachmentFileBaseName: 'attachment',
      attachmentFileExtension: 'png',
      context: AttachmentPathContext.Unknown,
      notePathOrFile: null,
      oldAttachmentPathOrFile: 'attachment.png',
      readAttachmentFileContent: null,
      shouldSkipGeneratedAttachmentFileName: true,
      shouldSkipMissingAttachmentFolderCreation: true
    });
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
