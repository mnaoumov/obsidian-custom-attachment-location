import type {
  App,
  TFile
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';

import { requestUrl } from 'obsidian';
import { runWithTimeout } from 'obsidian-dev-utils/async';
import { hasEmbedSyntax } from 'obsidian-dev-utils/obsidian/link';
import {
  basename,
  extname
} from 'obsidian-dev-utils/path';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { selfWriteRegistry } from './self-write-registry.ts';
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
  readonly extension: string;
}

const MAGIC_BYTES_LENGTH = 8;

/**
 * Maps magic bytes to file extensions for binary content detection.
 */
const MAGIC_BYTES_TO_EXTENSION: readonly MagicBytesEntry[] = [
  /* eslint-disable no-magic-numbers -- Magic bytes constants are clearer as hex literals. */
  { bytes: [0x89, 0x50, 0x4E, 0x47], extension: 'png' },
  { bytes: [0xFF, 0xD8, 0xFF], extension: 'jpg' },
  { bytes: [0x47, 0x49, 0x46, 0x38], extension: 'gif' },
  { bytes: [0x52, 0x49, 0x46, 0x46], extension: 'webp' },
  { bytes: [0x42, 0x4D], extension: 'bmp' }
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

interface NetworkImageDownloaderGenerateImageLinkParams {
  readonly attachmentFile: TFile;
  readonly link: NetworkImageLink;
  readonly noteFile: TFile;
}

interface NetworkImageLink {
  readonly alt: string;
  readonly endIndexExclusive: number;
  readonly startIndex: number;
  readonly url: string;
}

interface NetworkImageReplacement {
  readonly endIndexExclusive: number;
  readonly markdownLink: string;
  readonly startIndex: number;
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

    const replacements: NetworkImageReplacement[] = [];

    for (const link of networkLinks) {
      this.abortSignalComponent.abortSignal.throwIfAborted();

      try {
        const attachmentFile = await this.downloadAndSaveImage(link, noteFile);
        replacements.push({
          endIndexExclusive: link.endIndexExclusive,
          markdownLink: this.generateImageLink({ attachmentFile, link, noteFile }),
          startIndex: link.startIndex
        });
      } catch (error) {
        console.warn(`Failed to download network image: ${link.url}`, error);
      }
    }

    if (replacements.length > 0) {
      let newContent = content;
      // Splicing by position, and from the end backwards so the earlier offsets stay valid, keeps every occurrence separate: the same image
      // Expression repeated twice is downloaded twice and each copy gets its own link, which a text-keyed replacement would collapse into one.
      for (const replacement of replacements.reverse()) {
        newContent = newContent.slice(0, replacement.startIndex) + replacement.markdownLink + newContent.slice(replacement.endIndexExclusive);
      }
      await this.app.vault.modify(noteFile, newContent);
    }
  }

  private detectExtension(content: ArrayBuffer, contentType: null | string): string {
    if (contentType) {
      const mimeExtension = CONTENT_TYPE_TO_EXTENSION[contentType.toLowerCase()];
      if (mimeExtension) {
        return mimeExtension;
      }
    }

    const bytes = new Uint8Array(content.slice(0, MAGIC_BYTES_LENGTH));
    for (const { bytes: magic, extension } of MAGIC_BYTES_TO_EXTENSION) {
      if (magic.every((byte, index) => bytes[index] === byte)) {
        return extension;
      }
    }

    return 'png';
  }

  private async downloadAndSaveImage(link: NetworkImageLink, noteFile: TFile): Promise<TFile> {
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

    selfWriteRegistry.register(savePath);
    return await this.app.vault.createBinary(savePath, arrayBuffer);
  }

  private async downloadImage(url: string): Promise<DownloadImageResult> {
    const HTTP_ERROR_THRESHOLD = 400;
    const response = await runWithTimeout({
      operationFunction: () =>
        requestUrl({
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; Obsidian/1.0)'
          },
          method: 'GET',
          throw: false,
          url
        }),
      operationName: `Download network image ${url}`,
      timeoutInMilliseconds: this.pluginSettingsComponent.settings.getNetworkImageDownloadTimeoutInMilliseconds()
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
        endIndexExclusive: match.index + match[0].length,
        startIndex: match.index,
        url: ensureNonNullable(groups['url'])
      });
    }
    return links;
  }

  private generateImageLink(params: NetworkImageDownloaderGenerateImageLinkParams): string {
    const {
      attachmentFile,
      link,
      noteFile
    } = params;

    // A blank alt is passed as `undefined` so the plugin's own display-text handling applies, exactly as it does for a pasted attachment.
    const alias = link.alt.trim() ? link.alt : undefined;

    // Issue #50: going through `app.fileManager.generateMarkdownLink` is what honors the vault's "New link format" and "Use Wikilinks"
    // Settings, applies the plugin's own patch, and escapes the destination. Obsidian does not add the embed prefix itself, so the caller
    // Has to - otherwise the image would turn into a plain link. Another plugin patching the same method may already return an embed,
    // Which must not be prefixed twice.
    const markdownLink = this.app.fileManager.generateMarkdownLink(attachmentFile, noteFile.path, undefined, alias);
    return hasEmbedSyntax(markdownLink) ? markdownLink : `!${markdownLink}`;
  }

  private sanitizeFileName(name: string): string {
    const specialCharactersRegExp = this.pluginSettingsComponent.settings.specialCharactersRegExp;
    let sanitized = name.replace(specialCharactersRegExp, () => this.pluginSettingsComponent.settings.specialCharactersReplacement);
    sanitized = sanitized.replaceAll(/[/\\:*?"<>|]/gu, '_');
    sanitized = sanitized.replaceAll(/\s+/gu, ' ').trim();
    return sanitized || 'image';
  }
}
