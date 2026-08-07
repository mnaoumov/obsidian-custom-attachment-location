import type {
  App,
  FileManager,
  RequestUrlResponse,
  RequestUrlResponsePromise,
  TFile,
  Vault
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';

import { requestUrl } from 'obsidian';
import { noop } from 'obsidian-dev-utils/function';
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
  generateMarkdownLink: ReturnType<typeof vi.fn<FileManager['generateMarkdownLink']>>;
  getDownloadedImagePath: ReturnType<typeof vi.fn<AttachmentPathManager['getDownloadedImagePath']>>;
  modify: ReturnType<typeof vi.fn<Vault['modify']>>;
  noteFile: TFile;
  settings: PluginSettings;
}

let context: TestContext;

function createContext(): TestContext {
  const settings = new PluginSettings();
  settings.downloadNetworkImages = true;

  const cachedRead = vi.fn<Vault['cachedRead']>().mockResolvedValue('');
  const createBinary = vi.fn<Vault['createBinary']>().mockImplementation((path: string) => Promise.resolve(strictProxy<TFile>({ path })));
  const modify = vi.fn<Vault['modify']>().mockResolvedValue(undefined);

  const vault = strictProxy<Vault>({
    cachedRead,
    createBinary,
    modify
  });

  // Stands in for Obsidian's own link generation. The real one honors "New link format" / "Use Wikilinks" and escapes the destination,
  // Which is precisely what the downloader must delegate to rather than reimplement, so the stub only has to be recognizable.
  const generateMarkdownLink = vi.fn<FileManager['generateMarkdownLink']>().mockReturnValue('[generated](../assets/generated.png)');
  const fileManager = strictProxy<FileManager>({ generateMarkdownLink });

  const app = strictProxy<App>({
    fileManager,
    vault
  });

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
    generateMarkdownLink,
    getDownloadedImagePath,
    modify,
    noteFile,
    settings
  };
}

// A never-resolving request that simulates a hung download.
function createHangingRequest(): RequestUrlResponsePromise {
  return Object.assign(new Promise<RequestUrlResponse>(noop), {
    arrayBuffer: new Promise<ArrayBuffer>(noop),
    json: new Promise<unknown>(noop),
    text: new Promise<string>(noop)
  });
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
  context = createContext();
});

describe('NetworkImageDownloader', () => {
  describe('downloadNetworkImagesForNote', () => {
    it('should do nothing when downloading network images is disabled', async () => {
      context.settings.downloadNetworkImages = false;
      await context.downloader.downloadNetworkImagesForNote(context.noteFile);
      expect(context.cachedRead).not.toHaveBeenCalled();
      expect(mockRequestUrl).not.toHaveBeenCalled();
    });

    it('should do nothing when the note has no network image links', async () => {
      context.cachedRead.mockResolvedValue('# No images here, just [a local link](local.md).');
      await context.downloader.downloadNetworkImagesForNote(context.noteFile);
      expect(context.cachedRead).toHaveBeenCalledWith(context.noteFile);
      expect(mockRequestUrl).not.toHaveBeenCalled();
      expect(context.modify).not.toHaveBeenCalled();
    });

    it('should download a network image and replace the link with the local path', async () => {
      context.cachedRead.mockResolvedValue('![My Image](https://example.com/pic.png)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));
      context.getDownloadedImagePath.mockResolvedValue('assets/My Image.png');

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(context.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileExtension: 'png',
        fileName: 'My Image',
        noteFilePath: 'notes/note.md'
      }));
      expect(context.createBinary).toHaveBeenCalledWith('assets/My Image.png', expect.any(ArrayBuffer));

      // Issue #50: the link must come from Obsidian's own generator, not from the raw vault-relative save path.
      const [attachmentFile, sourcePath, subpath, alias] = context.generateMarkdownLink.mock.calls[0] ?? [];
      expect(attachmentFile?.path).toBe('assets/My Image.png');
      expect(sourcePath).toBe('notes/note.md');
      expect(subpath).toBeUndefined();
      expect(alias).toBe('My Image');

      expect(context.modify).toHaveBeenCalledWith(context.noteFile, '![generated](../assets/generated.png)');
    });

    it('should pass no alias when the alt text is blank, so the display-text settings apply', async () => {
      context.cachedRead.mockResolvedValue('![   ](https://example.com/pic.png)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      const alias = context.generateMarkdownLink.mock.calls[0]?.[3];
      expect(alias).toBeUndefined();
    });

    it('should replace only the image expression, leaving the same URL in prose untouched', async () => {
      context.cachedRead.mockResolvedValue('See https://example.com/pic.png for ![My Image](https://example.com/pic.png)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));
      context.getDownloadedImagePath.mockResolvedValue('assets/My Image.png');

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(context.modify).toHaveBeenCalledWith(
        context.noteFile,
        'See https://example.com/pic.png for ![generated](../assets/generated.png)'
      );
    });

    it('should give each occurrence of the same image expression its own link', async () => {
      const url = 'https://example.com/pic.png';
      context.cachedRead.mockResolvedValue(`![My Image](${url})\ntext\n![My Image](${url})`);
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));
      context.getDownloadedImagePath
        .mockResolvedValueOnce('assets/first.png')
        .mockResolvedValueOnce('assets/second.png');
      context.generateMarkdownLink
        .mockReturnValueOnce('[first](../assets/first.png)')
        .mockReturnValueOnce('[second](../assets/second.png)');

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      // Both copies are downloaded, so each one has to point at the file saved for it - keying the rewrite by the matched text instead
      // Would leave the first attachment orphaned and both embeds pointing at the second.
      expect(context.createBinary).toHaveBeenCalledTimes(2);
      expect(context.modify).toHaveBeenCalledWith(
        context.noteFile,
        '![first](../assets/first.png)\ntext\n![second](../assets/second.png)'
      );
    });

    it('should not add a second embed prefix when the generated link is already an embed', async () => {
      context.cachedRead.mockResolvedValue('![My Image](https://example.com/pic.png)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));

      // Another plugin patching `generateMarkdownLink` may hand back an embed already.
      context.generateMarkdownLink.mockReturnValue('![[assets/generated.png]]');

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(context.modify).toHaveBeenCalledWith(context.noteFile, '![[assets/generated.png]]');
    });

    it('should derive the base name from the URL when the alt text is empty', async () => {
      context.cachedRead.mockResolvedValue('![](https://example.com/photo.jpg)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0xFF, 0xD8, 0xFF]),
        headers: {}
      }));

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(context.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileExtension: 'jpg',
        fileName: 'photo'
      }));
    });

    it('should fall back to the image base name when neither alt nor URL provide one', async () => {
      context.cachedRead.mockResolvedValue('![](https://example.com/)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(context.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileName: 'image'
      }));
    });

    it('should fall back to the image base name when sanitizing removes every character', async () => {
      context.settings.specialCharactersReplacement = '';
      context.cachedRead.mockResolvedValue('![###](https://example.com/pic.png)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x89, 0x50, 0x4E, 0x47]),
        headers: { 'content-type': 'image/png' }
      }));

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(context.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileName: 'image'
      }));
    });

    it('should detect the extension from magic bytes when the content type is unknown', async () => {
      context.cachedRead.mockResolvedValue('![gif](https://example.com/anim)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x47, 0x49, 0x46, 0x38]),
        headers: { 'content-type': 'application/octet-stream' }
      }));

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(context.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileExtension: 'gif'
      }));
    });

    it('should fall back to png when the extension cannot be detected', async () => {
      context.cachedRead.mockResolvedValue('![blob](https://example.com/blob)');
      mockRequestUrl.mockResolvedValue(createResponse({
        arrayBuffer: toArrayBuffer([0x00, 0x01, 0x02, 0x03]),
        headers: { 'content-type': 'application/octet-stream' }
      }));

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(context.getDownloadedImagePath).toHaveBeenCalledWith(expect.objectContaining({
        fileExtension: 'png'
      }));
    });

    it('should warn and skip the image when the download fails', async () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      context.cachedRead.mockResolvedValue('![broken](https://example.com/missing.png)');
      mockRequestUrl.mockResolvedValue(createResponse({ status: 404 }));

      await context.downloader.downloadNetworkImagesForNote(context.noteFile);

      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('https://example.com/missing.png'), expect.any(Error));
      expect(context.createBinary).not.toHaveBeenCalled();
      expect(context.modify).not.toHaveBeenCalled();
      warnSpy.mockRestore();
    });

    it('should time out and skip the image when the download exceeds the configured timeout', async () => {
      vi.useFakeTimers();
      try {
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
        context.settings.networkImageDownloadTimeoutInSeconds = 5;
        context.cachedRead.mockResolvedValue('![slow](https://example.com/slow.png)');
        mockRequestUrl.mockReturnValue(createHangingRequest());

        const promise = context.downloader.downloadNetworkImagesForNote(context.noteFile);
        await vi.advanceTimersByTimeAsync(5000);
        await promise;

        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('https://example.com/slow.png'), expect.any(Error));
        expect(context.createBinary).not.toHaveBeenCalled();
        expect(context.modify).not.toHaveBeenCalled();
        warnSpy.mockRestore();
      } finally {
        vi.useRealTimers();
      }
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
        pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings: context.settings })
      });

      await expect(downloader.downloadNetworkImagesForNote(context.noteFile)).rejects.toThrow();
    });
  });
});
