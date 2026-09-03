import type {
  App,
  FileStats,
  TFile,
  Vault,
  Workspace
} from 'obsidian';

import { moment as moment_ } from 'obsidian';
import {
  castTo,
  extractDefaultExportInterop
} from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { ArrayBufferMap } from './array-buffer-map.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { ImageManager } from './image-manager.ts';
import type { ImageSizeMap } from './image-size-map.ts';
import type { MarkdownUrlMap } from './markdown-url-map.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';
import type { TokenValidator } from './token-validator.ts';

import { AttachmentSaver } from './attachment-saver.ts';
import { AttachmentRenameMode } from './plugin-settings.ts';

interface TestContext {
  convertToJpeg: ReturnType<typeof vi.fn<ImageManager['convertToJpeg']>>;
  createBinary: ReturnType<typeof vi.fn<Vault['createBinary']>>;
  getActiveFile: ReturnType<typeof vi.fn<Workspace['getActiveFile']>>;
  getAvailablePathForAttachments: ReturnType<typeof vi.fn<AttachmentPathManager['getAvailablePathForAttachments']>>;
  getFileStats: ReturnType<typeof vi.fn<ArrayBufferMap['getFileStats']>>;
  getGeneratedAttachmentFileBaseName: ReturnType<typeof vi.fn<AttachmentPathManager['getGeneratedAttachmentFileBaseName']>>;
  getImageSize: ReturnType<typeof vi.fn<ImageManager['getImageSize']>>;
  imageSizeMapSet: ReturnType<typeof vi.fn<ImageSizeMap['set']>>;
  isPastedImageBuffer: ReturnType<typeof vi.fn<ArrayBufferMap['isPastedImage']>>;
  isPathIgnored: ReturnType<typeof vi.fn<HandedOverSettingsComponent['isPathIgnored']>>;
  markdownUrlMapDelete: ReturnType<typeof vi.fn<MarkdownUrlMap['delete']>>;
  markdownUrlMapSet: ReturnType<typeof vi.fn<MarkdownUrlMap['set']>>;
  saver: AttachmentSaver;
  settings: PluginSettings;
}

const moment = extractDefaultExportInterop(moment_);

let context: TestContext;

function createSaver(): TestContext {
  const isPathIgnored = vi.fn<HandedOverSettingsComponent['isPathIgnored']>().mockReturnValue(false);
  const handedOverSettingsComponent = strictProxy<HandedOverSettingsComponent>({ isPathIgnored });
  const settings = castTo<PluginSettings>({
    attachmentRenameMode: AttachmentRenameMode.None,
    markdownUrlFormat: ''
  });

  const getActiveFile = vi.fn<Workspace['getActiveFile']>().mockReturnValue(createTFile({ path: 'note.md' }));
  const createBinary = vi.fn<Vault['createBinary']>().mockResolvedValue(createTFile({ name: 'saved.png', path: 'assets/saved.png' }));

  const app = strictProxy<App>({
    vault: strictProxy<Vault>({ createBinary }),
    workspace: strictProxy<Workspace>({ activeEditor: null, getActiveFile })
  });

  const getFileStats = vi.fn<ArrayBufferMap['getFileStats']>().mockReturnValue(undefined);
  const isPastedImageBuffer = vi.fn<ArrayBufferMap['isPastedImage']>().mockReturnValue(false);
  const arrayBufferMap = strictProxy<ArrayBufferMap>({ getFileStats, isPastedImage: isPastedImageBuffer });

  const getAvailablePathForAttachments = vi.fn<AttachmentPathManager['getAvailablePathForAttachments']>().mockResolvedValue('assets/saved.png');
  const getGeneratedAttachmentFileBaseName = vi.fn<AttachmentPathManager['getGeneratedAttachmentFileBaseName']>().mockResolvedValue('generated');
  const attachmentPathManager = strictProxy<AttachmentPathManager>({
    getAvailablePathForAttachments,
    getGeneratedAttachmentFileBaseName
  });

  const convertToJpeg = vi.fn<ImageManager['convertToJpeg']>().mockImplementation((params) =>
    Promise.resolve({
      attachmentFileContent: params.attachmentFileContent,
      attachmentFileExtension: params.attachmentFileExtension
    })
  );
  const getImageSize = vi.fn<ImageManager['getImageSize']>().mockResolvedValue(null);
  const imageManager = strictProxy<ImageManager>({ convertToJpeg, getImageSize });

  const imageSizeMapSet = vi.fn<ImageSizeMap['set']>();
  const imageSizeMap = strictProxy<ImageSizeMap>({ set: imageSizeMapSet });

  const markdownUrlMapSet = vi.fn<MarkdownUrlMap['set']>();
  const markdownUrlMapDelete = vi.fn<MarkdownUrlMap['delete']>();
  const markdownUrlMap = strictProxy<MarkdownUrlMap>({ delete: markdownUrlMapDelete, set: markdownUrlMapSet });

  const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({ settings });
  const tokenValidator = strictProxy<TokenValidator>({});

  const saver = new AttachmentSaver({
    app,
    arrayBufferMap,
    attachmentPathManager,
    handedOverSettingsComponent,
    imageManager,
    imageSizeMap,
    markdownUrlMap,
    pluginSettingsComponent,
    tokenValidator
  });

  return {
    convertToJpeg,
    createBinary,
    getActiveFile,
    getAvailablePathForAttachments,
    getFileStats,
    getGeneratedAttachmentFileBaseName,
    getImageSize,
    imageSizeMapSet,
    isPastedImageBuffer,
    isPathIgnored,
    markdownUrlMapDelete,
    markdownUrlMapSet,
    saver,
    settings
  };
}

function createStats(overrides: Partial<FileStats>): FileStats {
  return strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0, ...overrides });
}

function createTFile(overrides: Partial<TFile>): TFile {
  return strictProxy<TFile>(overrides);
}

beforeEach(() => {
  vi.clearAllMocks();
  context = createSaver();
});

describe('AttachmentSaver', () => {
  describe('saveAttachment', () => {
    it('should save without renaming when there is no active note file', async () => {
      context.getActiveFile.mockReturnValue(null);
      const result = await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(result.path).toBe('assets/saved.png');
      expect(context.convertToJpeg).not.toHaveBeenCalled();
      expect(context.getGeneratedAttachmentFileBaseName).not.toHaveBeenCalled();
    });

    it('should save without renaming when the active note path is ignored', async () => {
      context.isPathIgnored.mockReturnValue(true);
      const result = await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(result.path).toBe('assets/saved.png');
      expect(context.convertToJpeg).not.toHaveBeenCalled();
    });

    it('should not rename when the rename mode is None', async () => {
      context.settings.attachmentRenameMode = AttachmentRenameMode.None;
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.getGeneratedAttachmentFileBaseName).not.toHaveBeenCalled();
    });

    it('should rename when the rename mode is All', async () => {
      context.settings.attachmentRenameMode = AttachmentRenameMode.All;
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.getGeneratedAttachmentFileBaseName).toHaveBeenCalled();
    });

    it('should rename a recently pasted image when the rename mode is OnlyPastedImages', async () => {
      context.settings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      const timestamp = moment().format('YYYYMMDDHHmmss');
      await context.saver.saveAttachment({
        attachmentFileBaseName: `Pasted image ${timestamp}`,
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.getGeneratedAttachmentFileBaseName).toHaveBeenCalled();
      expect(context.convertToJpeg).toHaveBeenCalledWith(expect.objectContaining({ isPastedImage: true }));
    });

    it('should not treat a non-pasted-image base name as a pasted image', async () => {
      context.settings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.getGeneratedAttachmentFileBaseName).not.toHaveBeenCalled();
      expect(context.convertToJpeg).toHaveBeenCalledWith(expect.objectContaining({ isPastedImage: false }));
    });

    // Regression for issue #31: a clipboard image whose ArrayBuffer was flagged by the `insertFiles`
    // Interception is renamed in OnlyPastedImages mode even when its base name is not a
    // `Pasted image <timestamp>` name (e.g. a Windows 11 Win+Shift+S screenshot from a temp file).
    it('should rename a clipboard-flagged image in OnlyPastedImages mode despite a non-pasted base name', async () => {
      context.settings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      context.isPastedImageBuffer.mockReturnValue(true);
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'image',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.getGeneratedAttachmentFileBaseName).toHaveBeenCalled();
      expect(context.convertToJpeg).toHaveBeenCalledWith(expect.objectContaining({ isPastedImage: true }));
    });

    it('should not treat an invalid pasted-image timestamp as a pasted image', async () => {
      context.settings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'Pasted image 99999999999999',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.convertToJpeg).toHaveBeenCalledWith(expect.objectContaining({ isPastedImage: false }));
    });

    it('should not treat an old pasted image as a recent pasted image', async () => {
      context.settings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      const oldTimestamp = moment().subtract(1, 'hour').format('YYYYMMDDHHmmss');
      await context.saver.saveAttachment({
        attachmentFileBaseName: `Pasted image ${oldTimestamp}`,
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.convertToJpeg).toHaveBeenCalledWith(expect.objectContaining({ isPastedImage: false }));
    });

    it('should throw for an invalid rename mode', async () => {
      context.settings.attachmentRenameMode = castTo<AttachmentRenameMode>('invalid');
      await expect(context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      })).rejects.toThrow('Invalid attachment rename mode');
    });

    it('should adopt the converted extension and content from the image manager', async () => {
      context.settings.attachmentRenameMode = AttachmentRenameMode.None;
      const convertedContent = new ArrayBuffer(8);
      context.convertToJpeg.mockResolvedValue({
        attachmentFileContent: convertedContent,
        attachmentFileExtension: 'jpg'
      });
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.getAvailablePathForAttachments).toHaveBeenCalledWith(expect.objectContaining({
        attachmentFileExtension: 'jpg'
      }));
      const params = context.getAvailablePathForAttachments.mock.calls[0]?.[0];
      expect(await params?.readAttachmentFileContent?.()).toBe(convertedContent);
    });

    it('should set the markdown url when a markdown url format is configured', async () => {
      context.settings.markdownUrlFormat = 'plain-url';
      const result = await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.markdownUrlMapSet).toHaveBeenCalledWith({ path: result.path, url: 'plain-url' });
      expect(context.markdownUrlMapDelete).not.toHaveBeenCalled();
    });

    it('should use the file stats from the array buffer map for the markdown url substitutions', async () => {
      context.settings.markdownUrlFormat = 'plain-url';
      context.getFileStats.mockReturnValue(createStats({ ctime: 1, mtime: 2, size: 3 }));
      const result = await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.markdownUrlMapSet).toHaveBeenCalledWith({ path: result.path, url: 'plain-url' });
    });

    it('should delete the markdown url when no markdown url format is configured', async () => {
      context.settings.markdownUrlFormat = '';
      const result = await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.markdownUrlMapDelete).toHaveBeenCalledWith(result.path);
      expect(context.markdownUrlMapSet).not.toHaveBeenCalled();
    });
  });

  describe('saveAttachmentCore', () => {
    it('should record the image size when the image manager returns one', async () => {
      context.getImageSize.mockResolvedValue('100x200');
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.imageSizeMapSet).toHaveBeenCalledWith({ path: 'assets/saved.png', size: '100x200' });
    });

    it('should not record an image size when the image manager returns null', async () => {
      context.getImageSize.mockResolvedValue(null);
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileExtension: 'png'
      });
      expect(context.imageSizeMapSet).not.toHaveBeenCalled();
    });

    it('should pass truncated ctime and mtime to createBinary when stats are present', async () => {
      context.getFileStats.mockReturnValue(createStats({ ctime: 1234.9, mtime: 5678.1, size: 10 }));
      const content = new ArrayBuffer(4);
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: content,
        attachmentFileExtension: 'png'
      });
      expect(context.createBinary).toHaveBeenCalledWith('assets/saved.png', content, {
        ctime: 1234,
        mtime: 5678
      });
    });

    it('should omit ctime and mtime from createBinary options when stats are absent', async () => {
      context.getFileStats.mockReturnValue(undefined);
      const content = new ArrayBuffer(4);
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: content,
        attachmentFileExtension: 'png'
      });
      expect(context.createBinary).toHaveBeenCalledWith('assets/saved.png', content, {});
    });

    it('should omit ctime and mtime from createBinary options when stats are zero', async () => {
      context.getFileStats.mockReturnValue(createStats({ ctime: 0, mtime: 0, size: 0 }));
      const content = new ArrayBuffer(4);
      await context.saver.saveAttachment({
        attachmentFileBaseName: 'img',
        attachmentFileContent: content,
        attachmentFileExtension: 'png'
      });
      expect(context.createBinary).toHaveBeenCalledWith('assets/saved.png', content, {});
    });
  });
});
