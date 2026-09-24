import type {
  App,
  FileManager
} from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import {
  generateMarkdownLink,
  hasAngleBrackets,
  hasWikilinkSyntax,
  LinkStyle
} from 'obsidian-dev-utils/obsidian/link';
import { encodeUrl } from 'obsidian-dev-utils/url';

import type { ImageSizeMap } from '../image-size-map.ts';
import type { MarkdownUrlMap } from '../markdown-url-map.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

interface FileManagerGenerateMarkdownLinkPatchComponentConstructorParams {
  readonly app: App;
  readonly fileManager: FileManager;
  readonly imageSizeMap: ImageSizeMap;
  readonly markdownUrlMap: MarkdownUrlMap;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class FileManagerGenerateMarkdownLinkPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly fileManager: FileManager;
  private readonly imageSizeMap: ImageSizeMap;
  private readonly markdownUrlMap: MarkdownUrlMap;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: FileManagerGenerateMarkdownLinkPatchComponentConstructorParams) {
    super();
    this.app = params.app;
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
        if (alias === undefined) {
          const imageSize = this.imageSizeMap.getAndDelete(file.path);
          if (imageSize) {
            alias = imageSize;
          } else if (this.pluginSettingsComponent.settings.shouldSetLinkDisplayTextToAttachmentFileName && !this.pluginSettingsComponent.isNoteEx(file)) {
            // Issue #24: use the attachment's base name (without extension) as the link display text.
            // Notes are excluded so wiki/markdown links between notes keep Obsidian's default behavior.
            // A drawing the user treats as an attachment is not a note here, as it is not one when collected.
            alias = file.basename;
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
