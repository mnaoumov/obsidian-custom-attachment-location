import type { Vault as VaultOriginal } from 'obsidian';

import { AttachmentPathContext } from '@mnaoumov/obsidian-lib/attachment-path';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from './attachment-path-manager.ts';

import {
  SelfWriteClaim,
  selfWriteRegistry
} from '../externally-created-attachments/self-write-registry.ts';
import { VaultGetAvailablePathForAttachmentsPatchComponent } from './vault-get-available-path-for-attachments-patch-component.ts';

describe('VaultGetAvailablePathForAttachmentsPatchComponent', () => {
  let vault: VaultOriginal;
  let attachmentPathManager: AttachmentPathManager;
  let originalMethod: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    const appMock = App.createConfigured__();
    vault = appMock.vault.asOriginalType2__();
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
      shouldReplaceSpecialCharactersInKeptFileName: true,
      shouldSkipGeneratedAttachmentFileName: true,
      shouldSkipMissingAttachmentFolderCreation: true
    });
  });

  it('should claim the path it hands out as resolved for an outside caller, whose file name it kept (issue #65)', async () => {
    const component = createComponent();
    component.load();

    await vault.getAvailablePathForAttachments('Pasted Image', 'png', null);

    expect(selfWriteRegistry.consume('/extended/attachment/path')).toBe(SelfWriteClaim.OutsideCaller);
  });

  it('should graft no extra members onto the patched method', () => {
    /*
     * `extended` and `checkIsAttachmentUnitFolder` were removed in 15.0.0. Their replacements are the plugin API's
     * `getAvailablePathForAttachments` and `isAttachmentUnitFolder`.
     */
    const component = createComponent();
    component.load();

    expect(Reflect.get(vault.getAvailablePathForAttachments, 'extended')).toBeUndefined();
    expect(Reflect.get(vault.getAvailablePathForAttachments, 'checkIsAttachmentUnitFolder')).toBeUndefined();
  });
});
