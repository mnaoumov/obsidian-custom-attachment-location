import { blobToDataUrl } from 'obsidian-dev-utils/blob';
import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import {
  getImageSize,
  getMimeType
} from './image.ts';
import { DefaultImageSizeDimension } from './plugin-settings.ts';

vi.mock('obsidian-dev-utils/blob', () => ({
  blobToDataUrl: vi.fn()
}));

interface SettingsLike {
  defaultImageSize: string;
  defaultImageSizeDimension: DefaultImageSizeDimension;
}

const mockBlobToDataUrl = vi.mocked(blobToDataUrl);

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

function createComponent(settings: SettingsLike): PluginSettingsComponent {
  return castTo<PluginSettingsComponent>({ settings });
}

describe('image', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBlobToDataUrl.mockResolvedValue('data:image/png;base64,abc');
    vi.stubGlobal('Image', FakeImage);
    FakeImage.nextWidth = 200;
    FakeImage.nextHeight = 100;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('getMimeType', () => {
    it('should return the mime type for a known extension', () => {
      expect(getMimeType('PNG')).toBe('image/png');
    });

    it('should return null for an unknown extension', () => {
      expect(getMimeType('txt')).toBeNull();
    });
  });

  describe('getImageSize', () => {
    it('should return null for a non-image extension', async () => {
      const component = createComponent({ defaultImageSize: '100px', defaultImageSizeDimension: DefaultImageSizeDimension.Width });
      const result = await getImageSize('txt', new ArrayBuffer(0), component);
      expect(result).toBeNull();
    });

    it('should return null when defaultImageSize is empty', async () => {
      const component = createComponent({ defaultImageSize: '', defaultImageSizeDimension: DefaultImageSizeDimension.Width });
      const result = await getImageSize('png', new ArrayBuffer(0), component);
      expect(result).toBeNull();
    });

    it('should compute height from a pixel width', async () => {
      const component = createComponent({ defaultImageSize: '100px', defaultImageSizeDimension: DefaultImageSizeDimension.Width });
      const result = await getImageSize('png', new ArrayBuffer(0), component);
      expect(result).toBe('100x50');
    });

    it('should compute width from a pixel height', async () => {
      const component = createComponent({ defaultImageSize: '50px', defaultImageSizeDimension: DefaultImageSizeDimension.Height });
      const result = await getImageSize('png', new ArrayBuffer(0), component);
      expect(result).toBe('100x50');
    });

    it('should compute both dimensions from a percentage', async () => {
      const component = createComponent({ defaultImageSize: '50%', defaultImageSizeDimension: DefaultImageSizeDimension.Width });
      const result = await getImageSize('jpg', new ArrayBuffer(0), component);
      expect(result).toBe('100x50');
    });
  });
});
