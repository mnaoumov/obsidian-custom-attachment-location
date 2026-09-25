import type {
  App as AppOriginal,
  Vault as VaultOriginal
} from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  AttachmentPathContext,
  getCheckIsAttachmentUnitFolderFunction
} from 'obsidian-dev-utils/obsidian/attachment-path';
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
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { PluginSettings } from '../plugin-settings.ts';

import {
  SelfWriteClaim,
  selfWriteRegistry
} from '../self-write-registry.ts';
import { VaultGetAvailablePathForAttachmentsPatchComponent } from './vault-get-available-path-for-attachments-patch-component.ts';

interface PatchedMethodWithExtended {
  extended: () => Promise<string>;
}

interface SettingsLike {
  isAttachmentUnitFolder: (path: string) => boolean;
}

describe('VaultGetAvailablePathForAttachmentsPatchComponent', () => {
  let app: AppOriginal;
  let vault: VaultOriginal;
  let attachmentPathManager: AttachmentPathManager;
  let originalMethod: ReturnType<typeof vi.fn>;
  let pluginSettingsComponent: PluginSettingsComponent;
  let settings: SettingsLike;

  /**
   * Reads the designation back the way any consumer does — through the library, off the vault.
   *
   * @param folderPath - The vault-relative path of the folder.
   * @returns `true` when the folder is designated, `false` when it is not and when nobody published a
   * designation at all.
   */
  function checkIsAttachmentUnitFolder(folderPath: string): boolean {
    return getCheckIsAttachmentUnitFolderFunction(app)?.(folderPath) ?? false;
  }

  beforeEach(() => {
    const appMock = App.createConfigured__();
    app = appMock.asOriginalType__();
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
    settings = {
      isAttachmentUnitFolder: vi.fn<(path: string) => boolean>().mockReturnValue(false)
    };
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      settings: castTo<PluginSettings>(settings)
    });
  });

  function createComponent(): VaultGetAvailablePathForAttachmentsPatchComponent {
    return new VaultGetAvailablePathForAttachmentsPatchComponent({
      attachmentPathManager,
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

  it('should claim the path it hands out as resolved for an outside caller, whose file name it kept (issue #65)', async () => {
    const component = createComponent();
    component.load();

    await vault.getAvailablePathForAttachments('Pasted Image', 'png', null);

    expect(selfWriteRegistry.consume('/extended/attachment/path')).toBe(SelfWriteClaim.OutsideCaller);
  });

  it('should attach an extended method bound to the attachment path manager', async () => {
    const component = createComponent();
    component.load();

    const patchedMethod = castTo<PatchedMethodWithExtended>(vault.getAvailablePathForAttachments);
    const result = await patchedMethod.extended();

    expect(result).toBe('/extended/attachment/path');
    expect(vi.mocked(attachmentPathManager.getAvailablePathForAttachments)).toHaveBeenCalledTimes(1);
  });

  it('should publish the attachment unit folder designation read back from the vault', () => {
    vi.mocked(settings.isAttachmentUnitFolder).mockImplementation((path) => path === 'Materials/page_files');
    const component = createComponent();
    component.load();

    expect(checkIsAttachmentUnitFolder('Materials/page_files')).toBe(true);
    expect(checkIsAttachmentUnitFolder('Materials')).toBe(false);
  });

  it('should answer no designation before the patch is installed', () => {
    /*
     * A reader that runs against a vault no attachment-location plugin has patched — the other plugin
     * installed on its own, or this one still loading — gets `false`, not a crash.
     */
    expect(checkIsAttachmentUnitFolder('Materials/page_files')).toBe(false);
  });
});
