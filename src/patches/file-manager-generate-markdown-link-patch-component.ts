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

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

interface FileManagerGenerateMarkdownLinkPatchComponentConstructorParams {
  readonly app: App;
  readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  readonly fileManager: FileManager;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

export class FileManagerGenerateMarkdownLinkPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  private readonly fileManager: FileManager;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: FileManagerGenerateMarkdownLinkPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.fileManager = params.fileManager;
    this.customAttachmentLocationComponent = params.customAttachmentLocationComponent;
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
          const imageSize = this.customAttachmentLocationComponent.imageAttachmentSizeMap.get(file.path);
          if (imageSize) {
            this.customAttachmentLocationComponent.imageAttachmentSizeMap.delete(file.path);
            alias = imageSize;
          }
        }
        let defaultLink = originalMethodBound(file, sourcePath, subpath, alias);

        if (!this.pluginSettingsComponent.settings.markdownUrlFormat) {
          return defaultLink;
        }

        const markdownUrl = this.customAttachmentLocationComponent.pathMarkdownUrlMap.get(file.path);

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
