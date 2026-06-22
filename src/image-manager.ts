import {
  blobToDataUrl,
  blobToJpegArrayBuffer
} from 'obsidian-dev-utils/blob';
import { trimEnd } from 'obsidian-dev-utils/string';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import {
  ConvertImagesToJpegMode,
  DefaultImageSizeDimension
} from './plugin-settings.ts';

const IMAGE_MIME_TYPE_IMAGE_MAP: Record<string, string> = {
  avif: 'image/avif',
  bmp: 'image/bmp',
  gif: 'image/gif',
  jpeg: 'image/jpeg',
  jpg: 'image/jpeg',
  png: 'image/png',
  svg: 'image/svg+xml',
  webp: 'image/webp'
};

interface ImageManagerConstructorParams {
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

interface ImageManagerConvertToJpegParams {
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
  readonly isPastedImage: boolean;
}

interface ImageManagerConvertToJpegResult {
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
}

interface ImageManagerGetImageSizeParams {
  readonly content: ArrayBuffer;
  readonly extension: string;
}

export class ImageManager {
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: ImageManagerConstructorParams) {
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public async convertToJpeg(params: ImageManagerConvertToJpegParams): Promise<ImageManagerConvertToJpegResult> {
    const mimeType = this.getMimeType(params.attachmentFileExtension);
    let shouldConvertImageToJpeg = false;

    if (mimeType) {
      switch (this.pluginSettingsComponent.settings.convertImagesToJpegMode) {
        case ConvertImagesToJpegMode.AllImages:
          shouldConvertImageToJpeg = true;
          break;
        case ConvertImagesToJpegMode.AllImagesExceptAlreadyJpegFiles:
          if (mimeType !== 'image/jpeg') {
            shouldConvertImageToJpeg = true;
          }
          break;
        case ConvertImagesToJpegMode.None:
          break;
        case ConvertImagesToJpegMode.OnlyPastedClipboardPngImages:
          if (params.isPastedImage && mimeType === 'image/png') {
            shouldConvertImageToJpeg = true;
          }
          break;
        default:
          throw new Error(`Invalid convert images to JPEG mode: ${this.pluginSettingsComponent.settings.convertImagesToJpegMode as string}`);
      }
    }

    if (shouldConvertImageToJpeg && mimeType) {
      return {
        attachmentFileContent: await blobToJpegArrayBuffer(
          new Blob([params.attachmentFileContent], { type: mimeType }),
          this.pluginSettingsComponent.settings.jpegQuality
        ),
        attachmentFileExtension: 'jpg'
      };
    }

    return {
      attachmentFileContent: params.attachmentFileContent,
      attachmentFileExtension: params.attachmentFileExtension
    };
  }

  public async getImageSize(params: ImageManagerGetImageSizeParams): Promise<null | string> {
    const mimeType = IMAGE_MIME_TYPE_IMAGE_MAP[params.extension.toLowerCase()];
    if (!mimeType) {
      return null;
    }

    if (!this.pluginSettingsComponent.settings.defaultImageSize) {
      return null;
    }

    const blob = new Blob([params.content], { type: mimeType });
    const dataUrl = await blobToDataUrl(blob);
    const image = new Image();
    await new Promise((resolve) => {
      image.addEventListener('load', () => {
        resolve();
      });
      image.src = dataUrl;
    });

    let width: number;
    let height: number;

    const PX = 'px';
    const PERCENTAGE = '%';

    if (this.pluginSettingsComponent.settings.defaultImageSize.endsWith(PX)) {
      const dimensionInPixels = Number(trimEnd(this.pluginSettingsComponent.settings.defaultImageSize, PX));
      if (this.pluginSettingsComponent.settings.defaultImageSizeDimension === DefaultImageSizeDimension.Width) {
        width = dimensionInPixels;
        height = Math.trunc(width / image.width * image.height);
      } else {
        height = dimensionInPixels;
        width = Math.trunc(height / image.height * image.width);
      }
    } else {
      const percentage = Number(trimEnd(this.pluginSettingsComponent.settings.defaultImageSize, PERCENTAGE));
      const FULL_IMAGE_PERCENTAGE = 100;
      width = Math.trunc(image.width / FULL_IMAGE_PERCENTAGE * percentage);
      height = Math.trunc(image.height / FULL_IMAGE_PERCENTAGE * percentage);
    }

    return `${String(width)}x${String(height)}`;
  }

  public getMimeType(extension: string): null | string {
    return IMAGE_MIME_TYPE_IMAGE_MAP[extension.toLowerCase()] ?? null;
  }
}
