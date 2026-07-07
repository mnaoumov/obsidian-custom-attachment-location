import type {
  App,
  TFile
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';

import { requestUrl } from 'obsidian';
import {
  basename,
  extname
} from 'obsidian-dev-utils/path';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { ActionContext } from './token-evaluator-context.ts';

/**
 * Matches standard Markdown image tags with network URLs: ![alt](https://...)
 */
const NETWORK_IMAGE_PATTERN = /!\[(?<alt>.*?)\]\((?<url>https?:\/\/[^)]+)\)/g;

/**
 * Maps common Content-Type headers to file extensions.
 */
const CONTENT_TYPE_TO_EXTENSION: Record<string, string> = {
  'image/avif': 'avif',
  'image/bmp': 'bmp',
  'image/gif': 'gif',
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/svg+xml': 'svg',
  'image/tiff': 'tiff',
  'image/webp': 'webp'
};

interface MagicBytesEntry {
  readonly bytes: readonly number[];
  readonly ext: string;
}

const MAGIC_BYTES_LENGTH = 8;

/**
 * Maps magic bytes to file extensions for binary content detection.
 */
const MAGIC_BYTES_TO_EXTENSION: readonly MagicBytesEntry[] = [
  /* eslint-disable no-magic-numbers -- Magic bytes constants are clearer as hex literals. */
  { bytes: [0x89, 0x50, 0x4E, 0x47], ext: 'png' },
  { bytes: [0xFF, 0xD8, 0xFF], ext: 'jpg' },
  { bytes: [0x47, 0x49, 0x46, 0x38], ext: 'gif' },
  { bytes: [0x52, 0x49, 0x46, 0x46], ext: 'webp' },
  { bytes: [0x42, 0x4D], ext: 'bmp' }
  /* eslint-enable no-magic-numbers -- Magic bytes constants are clearer as hex literals. */
];

interface DownloadImageResult {
  readonly arrayBuffer: ArrayBuffer;
  readonly contentType: null | string;
}

interface NetworkImageDownloaderConstructorParams {
  readonly abortSignalComponent: AbortSignalComponent;
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

interface NetworkImageLink {
  readonly alt: string;
  readonly fullMatch: string;
  readonly url: string;
}

export class NetworkImageDownloader {
  private readonly abortSignalComponent: AbortSignalComponent;
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: NetworkImageDownloaderConstructorParams) {
    this.abortSignalComponent = params.abortSignalComponent;
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public async downloadNetworkImagesForNote(noteFile: TFile): Promise<void> {
    if (!this.pluginSettingsComponent.settings.downloadNetworkImages) {
      return;
    }

    const content = await this.app.vault.cachedRead(noteFile);
    const networkLinks = this.findNetworkImageLinks(content);
    if (networkLinks.length === 0) {
      return;
    }

    const replacements = new Map<string, string>();

    for (const link of networkLinks) {
      this.abortSignalComponent.abortSignal.throwIfAborted();

      try {
        const localPath = await this.downloadAndSaveImage(link, noteFile);
        replacements.set(link.url, localPath);
      } catch (error) {
        console.warn(`Failed to download network image: ${link.url}`, error);
      }
    }

    if (replacements.size > 0) {
      let newContent = content;
      for (const [networkUrl, localPath] of replacements) {
        newContent = newContent.replaceAll(networkUrl, localPath);
      }
      await this.app.vault.modify(noteFile, newContent);
    }
  }

  private detectExtension(content: ArrayBuffer, contentType: null | string): string {
    if (contentType) {
      const mimeExt = CONTENT_TYPE_TO_EXTENSION[contentType.toLowerCase()];
      if (mimeExt) {
        return mimeExt;
      }
    }

    const bytes = new Uint8Array(content.slice(0, MAGIC_BYTES_LENGTH));
    for (const { bytes: magic, ext } of MAGIC_BYTES_TO_EXTENSION) {
      if (magic.every((byte, index) => bytes[index] === byte)) {
        return ext;
      }
    }

    return 'png';
  }

  private async downloadAndSaveImage(link: NetworkImageLink, noteFile: TFile): Promise<string> {
    const { arrayBuffer, contentType } = await this.downloadImage(link.url);
    const extension = this.detectExtension(arrayBuffer, contentType);

    const urlPath = new URL(link.url).pathname;
    let baseName = link.alt.trim() || basename(urlPath, extname(urlPath)) || 'image';
    baseName = this.sanitizeFileName(baseName);

    const savePath = await this.attachmentPathManager.getDownloadedImagePath({
      actionContext: ActionContext.CollectAttachments,
      downloadedContent: arrayBuffer,
      fileExtension: extension,
      fileName: baseName,
      noteFilePath: noteFile.path
    });

    await this.app.vault.createBinary(savePath, arrayBuffer);
    return savePath;
  }

  private async downloadImage(url: string): Promise<DownloadImageResult> {
    const HTTP_ERROR_THRESHOLD = 400;
    const response = await requestUrl({
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; Obsidian/1.0)'
      },
      method: 'GET',
      throw: false,
      url
    });

    if (response.status >= HTTP_ERROR_THRESHOLD) {
      throw new Error(`HTTP ${String(response.status)}`);
    }

    const contentTypeHeader = response.headers['content-type'];
    const contentType = typeof contentTypeHeader === 'string' ? contentTypeHeader : null;
    return { arrayBuffer: response.arrayBuffer, contentType };
  }

  private findNetworkImageLinks(content: string): NetworkImageLink[] {
    const links: NetworkImageLink[] = [];
    for (const match of content.matchAll(NETWORK_IMAGE_PATTERN)) {
      const groups = ensureNonNullable(match.groups);
      links.push({
        alt: ensureNonNullable(groups['alt']),
        fullMatch: match[0],
        url: ensureNonNullable(groups['url'])
      });
    }
    return links;
  }

  private sanitizeFileName(name: string): string {
    const specialCharactersRegExp = this.pluginSettingsComponent.settings.specialCharactersRegExp;
    let sanitized = name.replace(specialCharactersRegExp, this.pluginSettingsComponent.settings.specialCharactersReplacement);
    sanitized = sanitized.replace(/[/\\:*?"<>|]/gu, '_');
    sanitized = sanitized.replace(/\s+/gu, ' ').trim();
    return sanitized || 'image';
  }
}
