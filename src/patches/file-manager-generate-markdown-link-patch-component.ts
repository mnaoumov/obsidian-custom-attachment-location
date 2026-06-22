import type {
  App,
  FileManager
} from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import {
  encodeUrl,
  generateMarkdownLink,
  LinkStyle,
  testAngleBrackets,
  testWikilink
} from 'obsidian-dev-utils/obsidian/link';

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
      methodName: 'generateMarkdownLink',
      obj: this.fileManager,
      patchHandler: ({
        originalArgs: [file, sourcePath, subpath, alias],
        originalMethodBound
      }) => {
        if (alias === undefined) {
          const imageSize = this.imageSizeMap.getAndDelete(file.path);
          if (imageSize) {
            alias = imageSize;
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

        if (testWikilink(defaultLink)) {
          defaultLink = generateMarkdownLink({
            app: this.app,
            linkStyle: LinkStyle.Markdown,
            originalLink: defaultLink,
            sourcePathOrFile: sourcePath,
            targetPathOrFile: file
          });
        }

        if (testAngleBrackets(defaultLink)) {
          return defaultLink.replace(/\]\(<.+?>\)/, `](<${markdownUrl}>)`);
        }

        return defaultLink.replace(/\]\(.+?\)/, `](${encodeUrl(markdownUrl)})`);
      }
    });
  }
}
