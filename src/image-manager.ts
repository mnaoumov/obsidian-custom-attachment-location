import {
  blobToDataUrl,
  blobToJpegArrayBuffer
} from 'obsidian-dev-utils/blob';
import { trimEnd } from 'obsidian-dev-utils/string';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { getImageMimeType } from './image-mime-types.ts';
import {
  ConvertImagesToJpegMode,
  DefaultImageSizeDimension
} from './plugin-settings.ts';

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
    const mimeType = getImageMimeType(params.attachmentFileExtension);
    let shouldConvertImageToJpeg = false;

    if (mimeType) {
      switch (this.pluginSettingsComponent.settings.convertImagesToJpegMode) {
        case ConvertImagesToJpegMode.AllImages: {
          shouldConvertImageToJpeg = true;
          break;
        }
        case ConvertImagesToJpegMode.AllImagesExceptAlreadyJpegFiles: {
          if (mimeType !== 'image/jpeg') {
            shouldConvertImageToJpeg = true;
          }
          break;
        }
        case ConvertImagesToJpegMode.None: {
          break;
        }
        case ConvertImagesToJpegMode.OnlyPastedClipboardPngImages: {
          if (params.isPastedImage && mimeType === 'image/png') {
            shouldConvertImageToJpeg = true;
          }
          break;
        }
        default: {
          throw new Error(`Invalid convert images to JPEG mode: ${this.pluginSettingsComponent.settings.convertImagesToJpegMode as string}`);
        }
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
    const mimeType = getImageMimeType(params.extension);
    if (!mimeType) {
      return null;
    }

    if (!this.pluginSettingsComponent.settings.defaultImageSize) {
      return null;
    }

    const blob = new Blob([params.content], { type: mimeType });
    const dataUrl = await blobToDataUrl(blob);
    const image = new Image();
    await new Promise<void>((resolve) => {
      image.addEventListener('load', () => {
        resolve();
      });
      image.src = dataUrl;
    });

    let width: number;

    const PX = 'px';
    const PERCENTAGE = '%';

    if (this.pluginSettingsComponent.settings.defaultImageSize.endsWith(PX)) {
      const dimensionInPixels = Number(trimEnd({
        $string: this.pluginSettingsComponent.settings.defaultImageSize,
        suffix: PX
      }));
      width = this.pluginSettingsComponent.settings.defaultImageSizeDimension === DefaultImageSizeDimension.Width ? dimensionInPixels : Math.trunc(dimensionInPixels / image.height * image.width);
    } else {
      const percentage = Number(trimEnd({
        $string: this.pluginSettingsComponent.settings.defaultImageSize,
        suffix: PERCENTAGE
      }));
      const FULL_IMAGE_PERCENTAGE = 100;
      width = Math.trunc(image.width / FULL_IMAGE_PERCENTAGE * percentage);
    }

    // Emit width only so Obsidian preserves the image's aspect ratio.
    // A fixed `WIDTHxHEIGHT` distorts images in constrained containers (table cells, Canvas).
    return String(width);
  }
}
