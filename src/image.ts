import { blobToDataUrl } from 'obsidian-dev-utils/blob';
import { trimEnd } from 'obsidian-dev-utils/string';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { DefaultImageSizeDimension } from './plugin-settings.ts';

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

export async function getImageSize(extension: string, content: ArrayBuffer, pluginSettingsComponent: PluginSettingsComponent): Promise<null | string> {
  const mimeType = IMAGE_MIME_TYPE_IMAGE_MAP[extension.toLowerCase()];
  if (!mimeType) {
    return null;
  }

  if (!pluginSettingsComponent.settings.defaultImageSize) {
    return null;
  }

  const blob = new Blob([content], { type: mimeType });
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

  if (pluginSettingsComponent.settings.defaultImageSize.endsWith(PX)) {
    const dimensionInPixels = Number(trimEnd(pluginSettingsComponent.settings.defaultImageSize, PX));
    if (pluginSettingsComponent.settings.defaultImageSizeDimension === DefaultImageSizeDimension.Width) {
      width = dimensionInPixels;
      height = Math.trunc(width / image.width * image.height);
    } else {
      height = dimensionInPixels;
      width = Math.trunc(height / image.height * image.width);
    }
  } else {
    const percentage = Number(trimEnd(pluginSettingsComponent.settings.defaultImageSize, PERCENTAGE));
    const FULL_IMAGE_PERCENTAGE = 100;
    width = Math.trunc(image.width / FULL_IMAGE_PERCENTAGE * percentage);
    height = Math.trunc(image.height / FULL_IMAGE_PERCENTAGE * percentage);
  }

  return `${String(width)}x${String(height)}`;
}

export function getMimeType(extension: string): null | string {
  return IMAGE_MIME_TYPE_IMAGE_MAP[extension.toLowerCase()] ?? null;
}
