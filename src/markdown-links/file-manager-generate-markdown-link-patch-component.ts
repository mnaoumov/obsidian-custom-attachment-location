import type {
  App,
  FileManager
} from 'obsidian';

import { MonkeyAroundComponent } from '@mnaoumov/obsidian-lib/components/monkey-around-component';
import {
  generateMarkdownLink,
  hasAngleBrackets,
  hasWikilinkSyntax,
  LinkStyle
} from '@mnaoumov/obsidian-lib/link';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';
import { encodeUrl } from '@mnaoumov/typescript-lib/url';

import type { AttachmentPathManager } from '../attachment-location/attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { ImageSizeMap } from './image-size-map.ts';
import type { MarkdownUrlMap } from './markdown-url-map.ts';

import { isImageExtension } from '../attachment-saving/image-mime-types.ts';

const FULL_WIDTH_ASCII_OFFSET = 0xFE_E0;

interface FileManagerGenerateMarkdownLinkPatchComponentConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly fileManager: FileManager;
  readonly imageSizeMap: ImageSizeMap;
  readonly markdownUrlMap: MarkdownUrlMap;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class FileManagerGenerateMarkdownLinkPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly fileManager: FileManager;
  private readonly imageSizeMap: ImageSizeMap;
  private readonly markdownUrlMap: MarkdownUrlMap;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: FileManagerGenerateMarkdownLinkPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.fileManager = params.fileManager;
    this.imageSizeMap = params.imageSizeMap;
    this.markdownUrlMap = params.markdownUrlMap;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public override onload(): void {
    this.registerMethodPatch({
      $object: this.fileManager,
      methodName: 'generateMarkdownLink',
      patchHandler: ({
        originalArguments: [file, sourcePath, subpath, alias],
        originalMethodBound
      }) => {
        const insertedLinkText = this.pluginSettingsComponent.settings.insertedLinkText && !isImageExtension(file.extension) && !this.pluginSettingsComponent.isNoteEx(file)
          ? this.attachmentPathManager.takeInsertedLinkText({ attachmentPath: file.path, notePath: sourcePath })
          : undefined;
        if (alias === undefined) {
          const imageSize = this.imageSizeMap.getAndDelete(file.path);
          if (imageSize) {
            alias = imageSize;
          } else if (!this.pluginSettingsComponent.isNoteEx(file)) {
            if (this.pluginSettingsComponent.settings.insertedLinkText && !isImageExtension(file.extension)) {
              alias = insertedLinkText ?? this.attachmentPathManager.getInsertedLinkText({ attachmentFile: file, notePath: sourcePath });
              // Full width equivalents cannot terminate a wiki alias, become a subpath, or open Markdown/HTML.
              alias = alias?.replaceAll(/[|[\]#^\\<>\r\n]/g, (character) => {
                return character === '\r' || character === '\n' ? ' ' : String.fromCodePoint(ensureNonNullable(character.codePointAt(0)) + FULL_WIDTH_ASCII_OFFSET);
              });
            }
            if (alias === undefined && this.pluginSettingsComponent.settings.shouldSetLinkDisplayTextToAttachmentFileName) {
              // Issue #24: use the attachment's base name (without extension) as the link display text.
              // Notes are excluded so wiki/markdown links between notes keep Obsidian's default behavior.
              // A drawing the user treats as an attachment is not a note here, as it is not one when collected.
              alias = file.basename;
            }
          }
        }
        let defaultLink = originalMethodBound(file, sourcePath, subpath, alias);

        if (!this.pluginSettingsComponent.settings.markdownUrlFormat) {
          return defaultLink;
        }

        const markdownUrl = this.markdownUrlMap.get(file.path);

        if (!markdownUrl) {
          return defaultLink;
        }

        if (hasWikilinkSyntax(defaultLink)) {
          defaultLink = generateMarkdownLink({
            app: this.app,
            linkStyle: LinkStyle.Markdown,
            originalLink: defaultLink,
            sourcePathOrFile: sourcePath,
            targetPathOrFile: file
          });
        }

        return hasAngleBrackets(defaultLink) ? defaultLink.replace(/\]\(<.+?>\)/, () => `](<${markdownUrl}>)`) : defaultLink.replace(/\]\(.+?\)/, () => `](${encodeUrl(markdownUrl)})`);
      }
    });
  }
}
