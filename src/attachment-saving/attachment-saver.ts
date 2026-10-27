import type {
  App,
  DataWriteOptions,
  TFile
} from 'obsidian';

import {
  extractDefaultExportInterop,
  normalizeOptionalProperties,
  removeUndefinedProperties
} from '@mnaoumov/typescript-lib/object-utils';
import { makeFileName } from '@mnaoumov/typescript-lib/path';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';
import { moment as moment_ } from 'obsidian';

import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { AttachmentPathManager } from '../attachment-location/attachment-path-manager.ts';
import type { ImageSizeMap } from '../markdown-links/image-size-map.ts';
import type { MarkdownUrlMap } from '../markdown-links/markdown-url-map.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { ArrayBufferMap } from './array-buffer-map.ts';
import type { ImageManager } from './image-manager.ts';

import { AttachmentRenameMode } from '../settings/plugin-settings.ts';
import { Substitutions } from '../tokens/substitutions.ts';
import {
  ActionContext,
  actionContextToAttachmentPathContext
} from '../tokens/token-evaluator-context.ts';
import { TokenValidator } from '../tokens/token-validator.ts';

interface AttachmentSaverConstructorParams {
  readonly app: App;
  readonly arrayBufferMap: ArrayBufferMap;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly imageManager: ImageManager;
  readonly imageSizeMap: ImageSizeMap;
  readonly markdownUrlMap: MarkdownUrlMap;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly tokenValidator: TokenValidator;
}

const PASTED_IMAGE_NAME_REG_EXP = /Pasted image (?<Timestamp>\d{14})/;
const PASTED_IMAGE_DATE_FORMAT = 'YYYYMMDDHHmmss';
const THRESHOLD_IN_SECONDS = 10;
const moment = extractDefaultExportInterop(moment_);

interface AttachmentSaverSaveAttachmentCoreParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
  readonly destinationPath?: string;
  readonly originalAttachmentFileName: string;
  readonly shouldReplaceSpecialCharactersInKeptFileName?: boolean;
}

interface AttachmentSaverSaveAttachmentParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
  readonly destinationPath?: string;
  readonly shouldKeepName?: boolean;
  readonly shouldPreserveContent?: boolean;
}

type AttachmentSaverSaveAttachmentWithRenamingParams = AttachmentSaverSaveAttachmentParams;

export class AttachmentSaver {
  private readonly app: App;
  private readonly arrayBufferMap: ArrayBufferMap;
  private readonly attachmentPathManager: AttachmentPathManager;

  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly imageManager: ImageManager;
  private readonly imageSizeMap: ImageSizeMap;
  private readonly markdownUrlMap: MarkdownUrlMap;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: AttachmentSaverConstructorParams) {
    this.app = params.app;
    this.arrayBufferMap = params.arrayBufferMap;
    this.attachmentPathManager = params.attachmentPathManager;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.imageManager = params.imageManager;
    this.imageSizeMap = params.imageSizeMap;
    this.markdownUrlMap = params.markdownUrlMap;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.tokenValidator = params.tokenValidator;
  }

  public async saveAttachment(params: AttachmentSaverSaveAttachmentParams): Promise<TFile> {
    const originalPath = this.arrayBufferMap.getSourcePath(params.attachmentFileContent);
    const file = await this.saveAttachmentWithRenaming(params);
    if (originalPath) {
      this.attachmentPathManager.originalAttachmentNamesComponent.setOriginalPath(file.path, originalPath);
    }
    return file;
  }

  private async saveAttachmentCore(params: AttachmentSaverSaveAttachmentCoreParams): Promise<TFile> {
    const noteFile = this.app.workspace.getActiveFile();
    const attachmentFileStats = this.arrayBufferMap.getFileStats(params.attachmentFileContent);

    const attachmentFileContent = params.attachmentFileContent;
    const attachmentPath = params.destinationPath ?? await this.attachmentPathManager.getAvailablePathForAttachments({
      attachmentFileBaseName: params.attachmentFileBaseName,
      attachmentFileExtension: params.attachmentFileExtension,
      attachmentFileStats,
      context: actionContextToAttachmentPathContext(ActionContext.SaveAttachment),
      notePathOrFile: noteFile,
      oldAttachmentPathOrFile: makeFileName({
        fileBaseName: params.attachmentFileBaseName,
        fileExtension: params.attachmentFileExtension
      }),
      originalAttachmentFileName: params.originalAttachmentFileName,
      readAttachmentFileContent: (): Promise<ArrayBuffer> => Promise.resolve(attachmentFileContent),
      shouldReplaceSpecialCharactersInKeptFileName: params.shouldReplaceSpecialCharactersInKeptFileName ?? false,
      shouldSkipDuplicateCheck: false,
      shouldSkipGeneratedAttachmentFileName: true,
      shouldSkipMissingAttachmentFolderCreation: false
    });

    if (params.destinationPath) {
      this.attachmentPathManager.originalAttachmentNamesComponent.expectArrival(attachmentPath, params.originalAttachmentFileName);
    }

    const imageSize = await this.imageManager.getImageSize({
      content: params.attachmentFileContent,
      extension: params.attachmentFileExtension
    });
    if (imageSize !== null) {
      this.imageSizeMap.set({ path: attachmentPath, size: imageSize });
    }

    return await this.app.vault.createBinary(
      attachmentPath,
      params.attachmentFileContent,
      removeUndefinedProperties(normalizeOptionalProperties<DataWriteOptions>({
        ctime: attachmentFileStats?.ctime ? Math.trunc(attachmentFileStats.ctime) : undefined,
        mtime: attachmentFileStats?.mtime ? Math.trunc(attachmentFileStats.mtime) : undefined
      }))
    );
  }

  private async saveAttachmentWithRenaming(params: AttachmentSaverSaveAttachmentWithRenamingParams): Promise<TFile> {
    let attachmentFileBaseName = params.attachmentFileBaseName;
    let attachmentFileContent = params.attachmentFileContent;
    let attachmentFileExtension = params.attachmentFileExtension;
    // Before the JPEG conversion and the rename, both of which change what the file is called.
    const originalAttachmentFileName = makeFileName({
      fileBaseName: params.attachmentFileBaseName,
      fileExtension: params.attachmentFileExtension
    });

    const activeNoteFile = this.app.workspace.getActiveFile();
    if (!activeNoteFile || this.handedOverSettingsComponent.isPathIgnored(activeNoteFile.path)) {
      return await this.saveAttachmentCore({
        ...params.destinationPath && { destinationPath: params.destinationPath },
        attachmentFileBaseName,
        attachmentFileContent,
        attachmentFileExtension,
        originalAttachmentFileName
      });
    }

    // Prefer the explicit clipboard signal recorded by the `insertFiles` interception (issue #31).
    // Genuine clipboard image pastes are flagged even when Obsidian does not use its
    // `Pasted image <timestamp>` naming, as with a Windows 11 Win+Shift+S screenshot from a
    // Snipping Tool temp file. The legacy filename heuristic below remains a fallback.
    let isPastedImage = this.arrayBufferMap.isPastedImage(attachmentFileContent);
    if (!isPastedImage) {
      const match = PASTED_IMAGE_NAME_REG_EXP.exec(attachmentFileBaseName);
      if (match) {
        const timestampString = ensureNonNullable(match.groups?.['Timestamp']);
        const parsedDate = moment(timestampString, PASTED_IMAGE_DATE_FORMAT);
        if (parsedDate.isValid() && moment().diff(parsedDate, 'seconds') < THRESHOLD_IN_SECONDS) {
          isPastedImage = true;
        }
      }
    }

    const convertImageToJpegResult = params.shouldPreserveContent ? { attachmentFileContent, attachmentFileExtension } : await this.imageManager.convertToJpeg({
      attachmentFileContent,
      attachmentFileExtension,
      isPastedImage
    });
    attachmentFileExtension = convertImageToJpegResult.attachmentFileExtension;
    attachmentFileContent = convertImageToJpegResult.attachmentFileContent;

    let shouldRename = false;

    switch (this.pluginSettingsComponent.settings.attachmentRenameMode) {
      case AttachmentRenameMode.All: {
        shouldRename = true;
        break;
      }
      case AttachmentRenameMode.None: {
        break;
      }
      case AttachmentRenameMode.OnlyPastedImages: {
        shouldRename = isPastedImage;
        break;
      }
      default: {
        throw new Error('Invalid attachment rename mode');
      }
    }

    if (shouldRename && !params.shouldKeepName && !params.destinationPath) {
      attachmentFileBaseName = await this.attachmentPathManager.getGeneratedAttachmentFileBaseName(
        new Substitutions({
          actionContext: ActionContext.SaveAttachment,
          app: this.app,
          attachmentFileContent,
          attachmentFileName: makeFileName({
            fileBaseName: attachmentFileBaseName,
            fileExtension: attachmentFileExtension
          }),
          attachmentFileStats: this.arrayBufferMap.getFileStats(attachmentFileContent),
          noteFilePath: activeNoteFile.path,
          originalAttachmentFileName,
          pluginSettingsComponent: this.pluginSettingsComponent,
          tokenValidator: this.tokenValidator
        })
      );
    }

    const attachmentFile = await this.saveAttachmentCore({
      ...params.destinationPath && { destinationPath: params.destinationPath },
      attachmentFileBaseName,
      attachmentFileContent,
      attachmentFileExtension,
      originalAttachmentFileName,
      shouldReplaceSpecialCharactersInKeptFileName: !shouldRename
    });
    if (this.pluginSettingsComponent.settings.markdownUrlFormat) {
      const markdownUrl = await new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        app: this.app,
        attachmentFileContent,
        attachmentFileName: makeFileName({
          fileBaseName: attachmentFileBaseName,
          fileExtension: attachmentFileExtension
        }),
        attachmentFileStats: this.arrayBufferMap.getFileStats(attachmentFileContent) ?? undefined,
        generatedAttachmentFileName: attachmentFile.name,
        generatedAttachmentFilePath: attachmentFile.path,
        noteFilePath: activeNoteFile.path,
        originalAttachmentFileName,
        pluginSettingsComponent: this.pluginSettingsComponent,
        tokenValidator: this.tokenValidator
      }).fillTemplate(this.pluginSettingsComponent.settings.markdownUrlFormat);
      this.markdownUrlMap.set({ path: attachmentFile.path, url: markdownUrl });
    } else {
      this.markdownUrlMap.delete(attachmentFile.path);
    }
    return attachmentFile;
  }
}
