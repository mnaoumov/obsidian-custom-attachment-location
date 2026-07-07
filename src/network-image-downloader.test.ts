import type {
  App,
  RequestUrlResponse,
  TFile,
  Vault
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';

import { requestUrl } from 'obsidian';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { NetworkImageDownloader } from './network-image-downloader.ts';
import { PluginSettings } from './plugin-settings.ts';

vi.mock('obsidian', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian')>(),
  requestUrl: vi.fn()
}));

const mockRequestUrl = vi.mocked(requestUrl);

interface TestContext {
  cachedRead: ReturnType<typeof vi.fn<Vault['cachedRead']>>;
  createBinary: ReturnType<typeof vi.fn<Vault['createBinary']>>;
  downloader: NetworkImageDownloader;
  getDownloadedImagePath: ReturnType<typeof vi.fn<AttachmentPathManager['getDownloadedImagePath']>>;
  modify: ReturnType<typeof vi.fn<Vault['modify']>>;
  noteFile: TFile;
  settings: PluginSettings;
}

let ctx: TestContext;

function createContext(): TestContext {
  const settings = new PluginSettings();
  settings.downloadNetworkImages = true;

  const cachedRead = vi.fn<Vault['cachedRead']>().mockResolvedValue('');
  const createBinary = vi.fn<Vault['createBinary']>().mockResolvedValue(strictProxy<TFile>({}));
  const modify = vi.fn<Vault['modify']>().mockResolvedValue(undefined);

  const vault = strictProxy<Vault>({
    cachedRead,
    createBinary,
    modify
  });
  const app = strictProxy<App>({ vault });

  const getDownloadedImagePath = vi.fn<AttachmentPathManager['getDownloadedImagePath']>().mockResolvedValue('assets/image.png');
  const attachmentPathManager = strictProxy<AttachmentPathManager>({ getDownloadedImagePath });

  const abortSignalComponent = strictProxy<AbortSignalComponent>({
    abortSignal: new AbortController().signal
  });

  const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({ settings });

  const downloader = new NetworkImageDownloader({
    abortSignalComponent,
    app,
    attachmentPathManager,
    pluginSettingsComponent
  });

  const noteFile = strictProxy<TFile>({ path: 'notes/note.md' });

  return {
    cachedRead,
    createBinary,
    downloader,
    getDownloadedImagePath,
    modify,
    noteFile,
    settings
  };
}

function createResponse(overrides: Partial<RequestUrlResponse>): RequestUrlResponse {
  return {
    arrayBuffer: overrides.arrayBuffer ?? new ArrayBuffer(0),
    headers: overrides.headers ?? {},
    json: null,
    status: overrides.status ?? 200,
    text: ''
  };
}

function toArrayBuffer(bytes: readonly number[]): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

beforeEach(() => {
  vi.clearAllMocks();
  ctx = createContext();
});

describe('NetworkImageDownloader', () => {
  describe('downloadNetworkImagesForNote', () => {
    it('should do nothing when downloading network images is disabled', async () => {
      ctx.settings.downloadNetworkImages = false;
      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);
      expect(ctx.cachedRead).not.toHaveBeenCalled();
      expect(mockRequestUrl).not.toHaveBeenCalled();
    });

    it('should do nothing when the note has no network image links', async () => {
      ctx.cachedRead.mockResolvedValue('# No images here, just [a local link](local.md).');
      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);
      expect(ctx.cachedRead).toHaveBeenCalledWith(ctx.noteFile);
      expect(mockRequestUrl).not.toHaveBeenCalled();
      expect(ctx.modify).not.toHaveBeenCalled();
    });

    it('should download a network image and replace the link with the local path', async () => {
      ctx.cachedRead.mockResolvedValue('![My Image](https://example.com/pic.png)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));
      ctx.getDownloadedImagePath.mockResolvedValue('assets/My Image.png');

      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);

      expect(ctx.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileExtension: 'png',
        fileName: 'My Image',
        noteFilePath: 'notes/note.md'
      }));
      expect(ctx.createBinary).toHaveBeenCalledWith('assets/My Image.png', expect.any(ArrayBuffer));
      expect(ctx.modify).toHaveBeenCalledWith(ctx.noteFile, '![My Image](assets/My Image.png)');
    });

    it('should derive the base name from the URL when the alt text is empty', async () => {
      ctx.cachedRead.mockResolvedValue('![](https://example.com/photo.jpg)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0xFF, 0xD8, 0xFF]),
        headers: {}
      }));

      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);

      expect(ctx.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileExtension: 'jpg',
        fileName: 'photo'
      }));
    });

    it('should fall back to the image base name when neither alt nor URL provide one', async () => {
      ctx.cachedRead.mockResolvedValue('![](https://example.com/)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));

      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);

      expect(ctx.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileName: 'image'
      }));
    });

    it('should fall back to the image base name when sanitizing removes every character', async () => {
      ctx.settings.specialCharactersReplacement = '';
      ctx.cachedRead.mockResolvedValue('![###](https://example.com/pic.png)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));

      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);

      expect(ctx.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileName: 'image'
      }));
    });

    it('should detect the extension from magic bytes when the content type is unknown', async () => {
      ctx.cachedRead.mockResolvedValue('![gif](https://example.com/anim)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x47, 0x49, 0x46, 0x38]),
        headers: { 'content-type': 'application/octet-stream' }
      }));

      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);

      expect(ctx.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileExtension: 'gif'
      }));
    });

    it('should fall back to png when the extension cannot be detected', async () => {
      ctx.cachedRead.mockResolvedValue('![blob](https://example.com/blob)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x00, 0x01, 0x02, 0x03]),
        headers: { 'content-type': 'application/octet-stream' }
      }));

      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);

      expect(ctx.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileExtension: 'png'
      }));
    });

    it('should warn and skip the image when the download fails', async () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      ctx.cachedRead.mockResolvedValue('![broken](https://example.com/missing.png)');
      mockRequestUrl.mockResolvedValue(createResponse({ status: 404 }));

      await ctx.downloader.downloadNetworkImagesForNote(ctx.noteFile);

      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('https://example.com/missing.png'), expect.any(Error));
      expect(ctx.createBinary).not.toHaveBeenCalled();
      expect(ctx.modify).not.toHaveBeenCalled();
      warnSpy.mockRestore();
    });

    it('should throw when the shared signal is already aborted', async () => {
      const abortController = new AbortController();
      abortController.abort();
      const abortSignalComponent = strictProxy<AbortSignalComponent>({ abortSignal: abortController.signal });
      const downloader = new NetworkImageDownloader({
        abortSignalComponent,
        app: strictProxy<App>({
          vault: strictProxy<Vault>({
            cachedRead: vi.fn<Vault['cachedRead']>().mockResolvedValue('![x](https://example.com/x.png)')
          })
        }),
        attachmentPathManager: strictProxy<AttachmentPathManager>({}),
        pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings: ctx.settings })
      });

      await expect(downloader.downloadNetworkImagesForNote(ctx.noteFile)).rejects.toThrow();
    });
  });
});
