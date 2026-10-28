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
import type { PluginSettings } from '../settings/plugin-settings.ts';
import type { SidecarAttachmentsComponent } from '../sidecars/sidecar-attachments-component.ts';
import type { TokenValidator } from '../tokens/token-validator.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';

import { findSidecarBase } from '../sidecars/sidecar-matcher.ts';
import {
  getShareImportOriginalFileName,
  IMPORT_FILES_PREFIX,
  ShareReceiverImportFilesPatchComponent
} from './share-receiver-import-files-patch-component.ts';

interface CapacitorApi {
  readonly convertFileSrc: (uri: string) => string;
}

interface CapacitorGlobal {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  Capacitor: CapacitorApi;
}

type ImportFilesFunction = (files: SharedFile[]) => Promise<void>;

interface ShareReceiverPrototype {
  readonly importFiles: ImportFilesFunction;
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

  it('should leave a shared note to core, which saves it through getAvailablePath and never strips the prefix', async () => {
    const component = createComponent();
    component.load();

    const files: SharedFile[] = [
      { name: 'Note.md', uri: 'file:///shared/Note.md' },
      { name: 'Upper.MD', uri: 'file:///shared/Upper.MD' },
      { name: 'photo.png', uri: 'file:///shared/photo.png' }
    ];

    await strictProxy<ShareReceiverPrototype>(shareReceiver).importFiles(files);

    expect(files.map((file) => file.name)).toEqual(['Note.md', 'Upper.MD', `${IMPORT_FILES_PREFIX}generated-name.png`]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(getShareImportOriginalFileName('Note.md')).toBeUndefined();
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

  describe('sidecars', () => {
    let reportUnpairedMock: ReturnType<typeof vi.fn<(path: string) => void>>;
    let sidecarAttachmentsComponent: SidecarAttachmentsComponent;

    beforeEach(() => {
      reportUnpairedMock = vi.fn<(path: string) => void>();
      sidecarAttachmentsComponent = strictProxy<SidecarAttachmentsComponent>({
        findBase: (name: string, names: readonly string[]) => findSidecarBase({ extensions: ['p7s', '.ASC', 'srt'], name, names }),
        reportUnpaired: reportUnpairedMock
      });
      pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
        settings: strictProxy<PluginSettings>({ duplicateNameSeparator: ' ' })
      });
      // Each generated name follows the shared file just fetched, so a test can tell which file was named.
      vi.mocked(attachmentPathManager.getGeneratedAttachmentFileBaseName).mockImplementation(() => {
        const uri = String(fetchMock.mock.lastCall?.[0]);
        return Promise.resolve(`gen-${uri.slice(uri.lastIndexOf('/') + 1).split('.', 1)[0] ?? ''}`);
      });
      vi.spyOn(app.vault, 'getAvailablePathForAttachments').mockImplementation((fileBaseName, extension) => Promise.resolve(`assets/${fileBaseName}.${extension}`));
    });

    function createSidecarComponent(): ShareReceiverImportFilesPatchComponent {
      return new ShareReceiverImportFilesPatchComponent({
        app,
        attachmentPathManager,
        pluginSettingsComponent,
        shareReceiver,
        sidecarAttachmentsComponent,
        tokenValidator
      });
    }

    async function importNames(names: readonly string[]): Promise<string[]> {
      const component = createSidecarComponent();
      component.load();
      const files: SharedFile[] = names.map((name) => ({ name, uri: `file:///shared/${name}` }));
      await strictProxy<ShareReceiverPrototype>(shareReceiver).importFiles(files);
      expect(importFilesMock).toHaveBeenCalledWith(files);
      return files.map((file) => file.name.slice(IMPORT_FILES_PREFIX.length));
    }

    it('should derive a companion name from its base, whichever comes first, and keep the input order', async () => {
      expect(await importNames(['document.html.p7s', 'document.html'])).toEqual(['gen-document.html.p7s', 'gen-document.html']);
      expect(vi.mocked(attachmentPathManager.getGeneratedAttachmentFileBaseName)).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(getShareImportOriginalFileName('gen-document.html.p7s')).toBe('document.html.p7s');
      expect(getShareImportOriginalFileName('gen-document.html')).toBe('document.html');
      expect(reportUnpairedMock).not.toHaveBeenCalled();
    });

    it('should follow chained signatures', async () => {
      expect(await importNames(['document.html.p7s.asc', 'document.html', 'document.html.p7s'])).toEqual([
        'gen-document.html.p7s.asc',
        'gen-document.html',
        'gen-document.html.p7s'
      ]);
    });

    it('should replace the extension of a companion that shares only the stem', async () => {
      expect(await importNames(['video.srt', 'video.mkv'])).toEqual(['gen-video.srt', 'gen-video.mkv']);
    });

    it('should keep and report an orphan or ambiguous sidecar', async () => {
      expect(await importNames(['signature.p7s', 'clip.srt', 'clip.mkv', 'clip.mp4'])).toEqual([
        'signature.p7s',
        'clip.srt',
        'gen-clip.mkv',
        'gen-clip.mp4'
      ]);
      expect(reportUnpairedMock.mock.calls).toEqual([['signature.p7s'], ['clip.srt']]);
    });

    it('should give a whole group the first suffix under which none of its names is taken', async () => {
      await app.vault.createFolder('assets');
      await app.vault.create('assets/gen-document.html.p7s', '');

      expect(await importNames(['document.html', 'document.html.p7s'])).toEqual(['gen-document 1.html', 'gen-document 1.html.p7s']);
      expect(getShareImportOriginalFileName('gen-document 1.html.p7s')).toBe('document.html.p7s');
    });

    it('should not hand two roots of one batch the same name', async () => {
      vi.mocked(attachmentPathManager.getGeneratedAttachmentFileBaseName).mockResolvedValue('same');

      expect(await importNames(['a.html', 'a.html.p7s', 'b.pdf', 'b.pdf.p7s', 'c.html'])).toEqual([
        'same.html',
        'same.html.p7s',
        'same.pdf',
        'same.pdf.p7s',
        'same 1.html'
      ]);
    });

    it('should leave a shared note out of pairing, so its signature is reported as an orphan', async () => {
      const component = createSidecarComponent();
      component.load();
      const files: SharedFile[] = ['note.md', 'note.md.p7s'].map((name) => ({ name, uri: `file:///shared/${name}` }));
      await strictProxy<ShareReceiverPrototype>(shareReceiver).importFiles(files);

      expect(files.map((file) => file.name)).toEqual(['note.md', `${IMPORT_FILES_PREFIX}note.md.p7s`]);
      expect(reportUnpairedMock.mock.calls).toEqual([['note.md.p7s']]);
    });

    it('should leave a batch without sidecars to core collision handling', async () => {
      expect(await importNames(['photo.png'])).toEqual(['gen-photo.png']);
      expect(app.vault.getAvailablePathForAttachments).not.toHaveBeenCalled();
    });
  });

  it('should delegate to the original method when there are no shared files', async () => {
    const component = createComponent();
    component.load();

    await strictProxy<ShareReceiverPrototype>(shareReceiver).importFiles([]);

    expect(fetchMock).not.toHaveBeenCalled();
    expect(importFilesMock).toHaveBeenCalledWith([]);
  });
});
