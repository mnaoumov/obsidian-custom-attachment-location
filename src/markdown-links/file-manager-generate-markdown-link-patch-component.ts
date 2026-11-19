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
  /**
   * Counts the patches this component installed. Only the newest one acts; an older one passes the call through.
   */
  private activePatchId = 0;
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly fileManager: FileManager;
  private readonly imageSizeMap: ImageSizeMap;
  // The wrapper the newest patch installed, to tell whether another plugin has patched the method since.
  private installedMethod: unknown = null;
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

  /**
   * Puts this patch back on top of `generateMarkdownLink` when another plugin has patched it since.
   *
   * A patch that never calls through, such as `Better Markdown Links`' one, hides every patch installed before it.
   * That plugin loads after this one in a typical vault, so its patch landed on top, and the inserted link text, the
   * pasted image size and the Markdown URL format were all silently skipped. Patches stack in install order, and
   * nothing announces a later one, so this checks right before Obsidian generates a link for a paste or a drop: a fresh
   * patch goes on top, and the old one becomes a pass-through, so no call is handled twice.
   */
  public ensureOutermost(): void {
    if (this.installedMethod !== null && Reflect.get(this.fileManager, 'generateMarkdownLink') === this.installedMethod) {
      return;
    }
    this.installPatch();
  }

  public override onload(): void {
    this.installPatch();
    // Both fire before Obsidian handles the gesture, so the links it then generates go through the patch on top.
    this.registerEvent(this.app.workspace.on('editor-paste', () => {
      this.ensureOutermost();
    }));
    this.registerEvent(this.app.workspace.on('editor-drop', () => {
      this.ensureOutermost();
    }));
  }

  private installPatch(): void {
    this.activePatchId++;
    const patchId = this.activePatchId;
    this.registerMethodPatch({
      $object: this.fileManager,
      methodName: 'generateMarkdownLink',
      patchHandler: ({
        originalArguments: [file, sourcePath, subpath, alias],
        originalMethodBound
      }) => {
        if (patchId !== this.activePatchId) {
          return originalMethodBound(file, sourcePath, subpath, alias);
        }
        const insertedLinkText = this.pluginSettingsComponent.settings.insertedLinkText && !isImageExtension(file.extension) && !this.pluginSettingsComponent.isNoteEx(file)
          ? this.attachmentPathManager.takeInsertedLinkText({ attachmentPath: file.path, notePath: sourcePath })
          : null;
        if (alias === undefined) {
          const imageSize = this.imageSizeMap.getAndDelete(file.path);
          if (imageSize) {
            alias = imageSize;
          } else if (this.pluginSettingsComponent.settings.insertedLinkText && !isImageExtension(file.extension) && !this.pluginSettingsComponent.isNoteEx(file)) {
            // Notes are excluded so links between notes keep Obsidian's default behavior. A drawing the user
            // treats as an attachment is not a note here, as it is not one when collected.
            const linkText = insertedLinkText ?? this.attachmentPathManager.getInsertedLinkText({ attachmentFile: file, notePath: sourcePath });
            // Full width equivalents cannot terminate a wiki alias, become a subpath, or open Markdown/HTML.
            alias = linkText?.replaceAll(/[|[\]#^\\<>\r\n]/g, (character) => {
              return character === '\r' || character === '\n' ? ' ' : String.fromCodePoint(ensureNonNullable(character.codePointAt(0)) + FULL_WIDTH_ASCII_OFFSET);
            }) ?? undefined;
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
    this.installedMethod = Reflect.get(this.fileManager, 'generateMarkdownLink');
  }
}
