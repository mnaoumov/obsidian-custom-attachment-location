import {
  blobToDataUrl,
  blobToJpegArrayBuffer
} from 'obsidian-dev-utils/blob';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';

import { ImageManager } from './image-manager.ts';
import {
  ConvertImagesToJpegMode,
  DefaultImageSizeDimension
} from './plugin-settings.ts';

vi.mock('obsidian-dev-utils/blob', () => ({
  blobToDataUrl: vi.fn<(blob: Blob) => Promise<string>>(),
  blobToJpegArrayBuffer: vi.fn<(blob: Blob, jpegQuality: number) => Promise<ArrayBuffer>>()
}));

const mockBlobToDataUrl = vi.mocked(blobToDataUrl);
const mockBlobToJpegArrayBuffer = vi.mocked(blobToJpegArrayBuffer);

class FakeImage {
  public static nextHeight = 0;
  public static nextWidth = 0;
  public height = 0;

  public width = 0;

  public get src(): string {
    return this.srcValue;
  }

  public set src(value: string) {
    this.srcValue = value;
    this.width = FakeImage.nextWidth;
    this.height = FakeImage.nextHeight;
    for (const listener of this.loadListeners) {
      listener();
    }
  }

  private readonly loadListeners: (() => void)[] = [];
  private srcValue = '';

  public addEventListener(_type: 'load', listener: () => void): void {
    this.loadListeners.push(listener);
  }
}

function createImageManager(settings: Partial<PluginSettings>): ImageManager {
  const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
    settings: castTo<PluginSettings>(settings)
  });
  return new ImageManager({ pluginSettingsComponent });
}

describe('ImageManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBlobToDataUrl.mockResolvedValue('data:image/png;base64,abc');
    mockBlobToJpegArrayBuffer.mockResolvedValue(new ArrayBuffer(8));
    vi.stubGlobal('Image', FakeImage);
    FakeImage.nextWidth = 200;
    FakeImage.nextHeight = 100;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('getMimeType', () => {
    it('should return the mime type for a known extension (case-insensitive)', () => {
      const imageManager = createImageManager({});
      expect(imageManager.getMimeType('PNG')).toBe('image/png');
    });

    it('should return null for an unknown extension', () => {
      const imageManager = createImageManager({});
      expect(imageManager.getMimeType('txt')).toBeNull();
    });
  });

  describe('getImageSize', () => {
    it('should return null for a non-image extension', async () => {
      const imageManager = createImageManager({
        defaultImageSize: '100px',
        defaultImageSizeDimension: DefaultImageSizeDimension.Width
      });
      const result = await imageManager.getImageSize({ content: new ArrayBuffer(0), extension: 'txt' });
      expect(result).toBeNull();
    });

    it('should return null when defaultImageSize is empty', async () => {
      const imageManager = createImageManager({
        defaultImageSize: '',
        defaultImageSizeDimension: DefaultImageSizeDimension.Width
      });
      const result = await imageManager.getImageSize({ content: new ArrayBuffer(0), extension: 'png' });
      expect(result).toBeNull();
    });

    it('should compute height from a pixel width', async () => {
      const imageManager = createImageManager({
        defaultImageSize: '100px',
        defaultImageSizeDimension: DefaultImageSizeDimension.Width
      });
      const result = await imageManager.getImageSize({ content: new ArrayBuffer(0), extension: 'png' });
      expect(result).toBe('100x50');
    });

    it('should compute width from a pixel height', async () => {
      const imageManager = createImageManager({
        defaultImageSize: '50px',
        defaultImageSizeDimension: DefaultImageSizeDimension.Height
      });
      const result = await imageManager.getImageSize({ content: new ArrayBuffer(0), extension: 'png' });
      expect(result).toBe('100x50');
    });

    it('should compute both dimensions from a percentage', async () => {
      const imageManager = createImageManager({
        defaultImageSize: '50%',
        defaultImageSizeDimension: DefaultImageSizeDimension.Width
      });
      const result = await imageManager.getImageSize({ content: new ArrayBuffer(0), extension: 'jpg' });
      expect(result).toBe('100x50');
    });
  });

  describe('convertToJpeg', () => {
    it('should not convert when the extension has no known mime type', async () => {
      const imageManager = createImageManager({ convertImagesToJpegMode: ConvertImagesToJpegMode.AllImages });
      const content = new ArrayBuffer(4);
      const result = await imageManager.convertToJpeg({
        attachmentFileContent: content,
        attachmentFileExtension: 'txt',
        isPastedImage: true
      });
      expect(result.attachmentFileExtension).toBe('txt');
      expect(result.attachmentFileContent).toBe(content);
      expect(mockBlobToJpegArrayBuffer).not.toHaveBeenCalled();
    });

    it('should convert any image in AllImages mode', async () => {
      const jpegContent = new ArrayBuffer(8);
      mockBlobToJpegArrayBuffer.mockResolvedValue(jpegContent);
      const imageManager = createImageManager({
        convertImagesToJpegMode: ConvertImagesToJpegMode.AllImages,
        jpegQuality: 0.5
      });
      const result = await imageManager.convertToJpeg({
        attachmentFileContent: new ArrayBuffer(4),
        attachmentFileExtension: 'png',
        isPastedImage: false
      });
      expect(result.attachmentFileExtension).toBe('jpg');
      expect(result.attachmentFileContent).toBe(jpegContent);
      expect(mockBlobToJpegArrayBuffer).toHaveBeenCalledWith(expect.any(Blob), 0.5);
    });

    it('should convert non-jpeg images in AllImagesExceptAlreadyJpegFiles mode', async () => {
      const imageManager = createImageManager({
        convertImagesToJpegMode: ConvertImagesToJpegMode.AllImagesExceptAlreadyJpegFiles,
        jpegQuality: 0.8
      });
      const result = await imageManager.convertToJpeg({
        attachmentFileContent: new ArrayBuffer(4),
        attachmentFileExtension: 'png',
        isPastedImage: false
      });
      expect(result.attachmentFileExtension).toBe('jpg');
      expect(mockBlobToJpegArrayBuffer).toHaveBeenCalled();
    });

    it('should not convert already-jpeg images in AllImagesExceptAlreadyJpegFiles mode', async () => {
      const content = new ArrayBuffer(4);
      const imageManager = createImageManager({
        convertImagesToJpegMode: ConvertImagesToJpegMode.AllImagesExceptAlreadyJpegFiles,
        jpegQuality: 0.8
      });
      const result = await imageManager.convertToJpeg({
        attachmentFileContent: content,
        attachmentFileExtension: 'jpg',
        isPastedImage: false
      });
      expect(result.attachmentFileExtension).toBe('jpg');
      expect(result.attachmentFileContent).toBe(content);
      expect(mockBlobToJpegArrayBuffer).not.toHaveBeenCalled();
    });

    it('should not convert in None mode', async () => {
      const content = new ArrayBuffer(4);
      const imageManager = createImageManager({ convertImagesToJpegMode: ConvertImagesToJpegMode.None });
      const result = await imageManager.convertToJpeg({
        attachmentFileContent: content,
        attachmentFileExtension: 'png',
        isPastedImage: true
      });
      expect(result.attachmentFileExtension).toBe('png');
      expect(result.attachmentFileContent).toBe(content);
      expect(mockBlobToJpegArrayBuffer).not.toHaveBeenCalled();
    });

    it('should convert a pasted PNG image in OnlyPastedClipboardPngImages mode', async () => {
      const imageManager = createImageManager({
        convertImagesToJpegMode: ConvertImagesToJpegMode.OnlyPastedClipboardPngImages,
        jpegQuality: 0.8
      });
      const result = await imageManager.convertToJpeg({
        attachmentFileContent: new ArrayBuffer(4),
        attachmentFileExtension: 'png',
        isPastedImage: true
      });
      expect(result.attachmentFileExtension).toBe('jpg');
      expect(mockBlobToJpegArrayBuffer).toHaveBeenCalled();
    });

    it('should not convert a non-pasted PNG image in OnlyPastedClipboardPngImages mode', async () => {
      const content = new ArrayBuffer(4);
      const imageManager = createImageManager({
        convertImagesToJpegMode: ConvertImagesToJpegMode.OnlyPastedClipboardPngImages,
        jpegQuality: 0.8
      });
      const result = await imageManager.convertToJpeg({
        attachmentFileContent: content,
        attachmentFileExtension: 'png',
        isPastedImage: false
      });
      expect(result.attachmentFileExtension).toBe('png');
      expect(result.attachmentFileContent).toBe(content);
      expect(mockBlobToJpegArrayBuffer).not.toHaveBeenCalled();
    });

    it('should not convert a pasted non-PNG image in OnlyPastedClipboardPngImages mode', async () => {
      const content = new ArrayBuffer(4);
      const imageManager = createImageManager({
        convertImagesToJpegMode: ConvertImagesToJpegMode.OnlyPastedClipboardPngImages,
        jpegQuality: 0.8
      });
      const result = await imageManager.convertToJpeg({
        attachmentFileContent: content,
        attachmentFileExtension: 'gif',
        isPastedImage: true
      });
      expect(result.attachmentFileExtension).toBe('gif');
      expect(result.attachmentFileContent).toBe(content);
      expect(mockBlobToJpegArrayBuffer).not.toHaveBeenCalled();
    });

    it('should throw for an invalid convert images to JPEG mode', async () => {
      const imageManager = createImageManager({
        convertImagesToJpegMode: castTo<ConvertImagesToJpegMode>('Bogus')
      });
      await expect(imageManager.convertToJpeg({
        attachmentFileContent: new ArrayBuffer(4),
        attachmentFileExtension: 'png',
        isPastedImage: true
      })).rejects.toThrow('Invalid convert images to JPEG mode: Bogus');
    });
  });
});
