import type {
  SharedFile,
  ShareReceiver
} from '@obsidian-typings/obsidian-public-latest';
import type { App as AppOriginal } from 'obsidian';

import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { TokenValidator } from '../token-validator.ts';

import {
  IMPORT_FILES_PREFIX,
  ShareReceiverImportFilesPatchComponent
} from './share-receiver-import-files-patch-component.ts';

interface CapacitorApi {
  convertFileSrc(uri: string): string;
}

interface CapacitorGlobal {
  Capacitor: CapacitorApi;
}

type ImportFilesFn = (files: SharedFile[]) => Promise<void>;

interface ShareReceiverProto {
  importFiles: ImportFilesFn;
}

describe('ShareReceiverImportFilesPatchComponent', () => {
  let app: AppOriginal;
  let attachmentPathManager: AttachmentPathManager;
  let pluginSettingsComponent: PluginSettingsComponent;
  let tokenValidator: TokenValidator;
  let importFilesMock: ReturnType<typeof vi.fn<ImportFilesFn>>;
  let shareReceiverProto: ShareReceiverProto;
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

    importFilesMock = vi.fn<ImportFilesFn>().mockResolvedValue(undefined);
    shareReceiverProto = {
      importFiles: importFilesMock
    };
    shareReceiver = strictProxy<ShareReceiver>(Object.create(shareReceiverProto));

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

    await strictProxy<ShareReceiverProto>(shareReceiver).importFiles(files);

    expect(convertFileSrcMock).toHaveBeenCalledWith('file:///shared/original.png');
    expect(fetchMock).toHaveBeenCalledWith('capacitor://file:///shared/original.png');
    expect(vi.mocked(attachmentPathManager.getGeneratedAttachmentFileBaseName)).toHaveBeenCalledTimes(1);
    expect(files[0]?.name).toBe(`${IMPORT_FILES_PREFIX}generated-name.png`);
    expect(importFilesMock).toHaveBeenCalledWith(files);
  });

  it('should delegate to the original method when there are no shared files', async () => {
    const component = createComponent();
    component.load();

    await strictProxy<ShareReceiverProto>(shareReceiver).importFiles([]);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(importFilesMock).toHaveBeenCalledWith([]);
  });
});
