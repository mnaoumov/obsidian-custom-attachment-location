import type {
  SharedFile,
  ShareReceiver
} from '@obsidian-typings/obsidian-public-latest';
import type { App as AppOriginal } from 'obsidian';

import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { TokenValidator } from '../tokens/token-validator.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';

import {
  getShareImportOriginalFileName,
  IMPORT_FILES_PREFIX,
  ShareReceiverImportFilesPatchComponent
} from './share-receiver-import-files-patch-component.ts';

interface CapacitorApi {
  convertFileSrc: (uri: string) => string;
}

interface CapacitorGlobal {
  Capacitor: CapacitorApi;
}

type ImportFilesFunction = (files: SharedFile[]) => Promise<void>;

interface ShareReceiverPrototype {
  importFiles: ImportFilesFunction;
}

describe('ShareReceiverImportFilesPatchComponent', () => {
  let app: AppOriginal;
  let attachmentPathManager: AttachmentPathManager;
  let pluginSettingsComponent: PluginSettingsComponent;
  let tokenValidator: TokenValidator;
  let importFilesMock: ReturnType<typeof vi.fn<ImportFilesFunction>>;
  let shareReceiverPrototype: ShareReceiverPrototype;
  let shareReceiver: ShareReceiver;
  let convertFileSrcMock: ReturnType<typeof vi.fn<(uri: string) => string>>;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    app = App.createConfigured__().asOriginalType__();
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getGeneratedAttachmentFileBaseName: vi.fn().mockResolvedValue('generated-name')
    });
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({});
    tokenValidator = strictProxy<TokenValidator>({});

    importFilesMock = vi.fn<ImportFilesFunction>().mockResolvedValue(undefined);
    shareReceiverPrototype = {
      importFiles: importFilesMock
    };
    shareReceiver = strictProxy<ShareReceiver>(Object.create(shareReceiverPrototype));

    convertFileSrcMock = vi.fn((uri: string): string => `capacitor://${uri}`);
    strictProxy<CapacitorGlobal>(window).Capacitor = {
      convertFileSrc: (uri: string): string => convertFileSrcMock(uri)
    };

    fetchMock = vi.fn().mockResolvedValue({
      arrayBuffer: (): Promise<ArrayBuffer> => Promise.resolve(new ArrayBuffer(8))
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function createComponent(): ShareReceiverImportFilesPatchComponent {
    return new ShareReceiverImportFilesPatchComponent({
      app,
      attachmentPathManager,
      pluginSettingsComponent,
      shareReceiver,
      tokenValidator
    });
  }

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should rewrite each shared file name with the generated base name and delegate to the original method', async () => {
    const component = createComponent();
    component.load();

    const files: SharedFile[] = [{
      name: 'original.png',
      uri: 'file:///shared/original.png'
    }];

    await strictProxy<ShareReceiverPrototype>(shareReceiver).importFiles(files);

    expect(convertFileSrcMock).toHaveBeenCalledWith('file:///shared/original.png');
    expect(fetchMock).toHaveBeenCalledWith('capacitor://file:///shared/original.png');
    expect(vi.mocked(attachmentPathManager.getGeneratedAttachmentFileBaseName)).toHaveBeenCalledTimes(1);
    expect(files[0]?.name).toBe(`${IMPORT_FILES_PREFIX}generated-name.png`);
    expect(importFilesMock).toHaveBeenCalledWith(files);
  });

  it('should remember the name each shared file arrived with under the name it generated', async () => {
    vi.mocked(attachmentPathManager.getGeneratedAttachmentFileBaseName).mockResolvedValue('generated-for-memory');
    const component = createComponent();
    component.load();

    await strictProxy<ShareReceiverPrototype>(shareReceiver).importFiles([{
      name: 'Shared photo.jpg',
      uri: 'file:///shared/photo.jpg'
    }]);

    expect(getShareImportOriginalFileName('generated-for-memory.jpg')).toBe('Shared photo.jpg');
    expect(getShareImportOriginalFileName('never-shared.jpg')).toBeUndefined();
  });

  it('should keep only the most recent shared names', async () => {
    let index = 0;
    vi.mocked(attachmentPathManager.getGeneratedAttachmentFileBaseName).mockImplementation(() => Promise.resolve(`bounded-${String(index++)}`));
    const component = createComponent();
    component.load();

    // One more than the bound the component keeps.
    const files: SharedFile[] = Array.from({ length: 101 }, (_, fileIndex) => ({
      name: `shared-${String(fileIndex)}.png`,
      uri: `file:///shared/${String(fileIndex)}.png`
    }));
    await strictProxy<ShareReceiverPrototype>(shareReceiver).importFiles(files);

    expect(getShareImportOriginalFileName('bounded-0.png')).toBeUndefined();
    expect(getShareImportOriginalFileName('bounded-100.png')).toBe('shared-100.png');
  });

  it('should delegate to the original method when there are no shared files', async () => {
    const component = createComponent();
    component.load();

    await strictProxy<ShareReceiverPrototype>(shareReceiver).importFiles([]);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(importFilesMock).toHaveBeenCalledWith([]);
  });
});
