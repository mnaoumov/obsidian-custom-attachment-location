import type {
  App,
  DataWriteOptions,
  FileStats,
  TFile
} from 'obsidian';
import type { AttachmentPathContext } from 'obsidian-dev-utils/obsidian/attachment-path';
import type { PathOrFile } from 'obsidian-dev-utils/obsidian/file-system';

import {
  isReferenceCache,
  parentFolderPath
} from '@obsidian-typings/obsidian-public-latest/implementations';
import {
  moment as moment_,
  Vault
} from 'obsidian';
import {
  extractDefaultExportInterop,
  normalizeOptionalProperties,
  removeUndefinedProperties
} from 'obsidian-dev-utils/object-utils';
import {
  DUMMY_PATH,
  getAvailablePathForAttachments
} from 'obsidian-dev-utils/obsidian/attachment-path';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import {
  getFileOrNull,
  getPath,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { extractLinkFile } from 'obsidian-dev-utils/obsidian/link';
import {
  getAllLinks,
  getCacheSafe
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { createFolderSafe } from 'obsidian-dev-utils/obsidian/vault';
import {
  basename,
  dirname,
  join,
  makeFileName
} from 'obsidian-dev-utils/path';
import { trimStart } from 'obsidian-dev-utils/string';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { ArrayBufferMap } from './array-buffer-map.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { ImageManager } from './image-manager.ts';
import type { ImageSizeMap } from './image-size-map.ts';
import type { MarkdownUrlMap } from './markdown-url-map.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { IMPORT_FILES_PREFIX } from './patches/share-receiver-import-files-patch-component.ts';
import { AttachmentRenameMode } from './plugin-settings.ts';
import { Substitutions } from './substitutions.ts';
import {
  ActionContext,
  actionContextToAttachmentPathContext,
  attachmentPathContextToActionContext
} from './token-evaluator-context.ts';

interface AttachmentSaverConstructorParams {
  readonly app: App;
  readonly arrayBufferMap: ArrayBufferMap;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly imageManager: ImageManager;
  readonly imageSizeMap: ImageSizeMap;
  readonly markdownUrlMap: MarkdownUrlMap;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

const PASTED_IMAGE_NAME_REG_EXP = /Pasted image (?<Timestamp>\d{14})/;
const PASTED_IMAGE_DATE_FORMAT = 'YYYYMMDDHHmmss';
const THRESHOLD_IN_SECONDS = 10;
const moment = extractDefaultExportInterop(moment_);

export interface AttachmentSaverGetAvailablePathForAttachmentsParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileContent?: ArrayBuffer | undefined;
  readonly attachmentFileExtension: string;
  readonly attachmentFileStats?: FileStats | undefined;
  readonly context: AttachmentPathContext;
  readonly notePathOrFile: null | PathOrFile;
  readonly oldAttachmentPathOrFile: PathOrFile;
  readonly oldNotePathOrFile?: PathOrFile | undefined;
  readonly shouldSkipDuplicateCheck?: boolean;
  readonly shouldSkipGeneratedAttachmentFileName?: boolean;
  readonly shouldSkipMissingAttachmentFolderCreation: boolean | undefined;
}

interface AttachmentSaverSaveAttachmentCoreParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
}

interface AttachmentSaverSaveAttachmentParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
}

type GetAvailablePathForAttachmentsFn = Vault['getAvailablePathForAttachments'];

export class AttachmentSaver {
  private readonly app: App;
  private readonly arrayBufferMap: ArrayBufferMap;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFn | null = null;

  private readonly imageManager: ImageManager;
  private readonly imageSizeMap: ImageSizeMap;
  private readonly markdownUrlMap: MarkdownUrlMap;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: AttachmentSaverConstructorParams) {
    this.app = params.app;
    this.arrayBufferMap = params.arrayBufferMap;
    this.attachmentPathManager = params.attachmentPathManager;
    this.imageManager = params.imageManager;
    this.imageSizeMap = params.imageSizeMap;
    this.markdownUrlMap = params.markdownUrlMap;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public async getAvailablePathForAttachments(params: AttachmentSaverGetAvailablePathForAttachmentsParams): Promise<string> {
    let attachmentFileBaseName = params.attachmentFileBaseName;
    let attachmentFileContent = params.attachmentFileContent;
    let attachmentFileStats = params.attachmentFileStats;
    let shouldSkipGeneratedAttachmentFileName = params.shouldSkipGeneratedAttachmentFileName;

    if (attachmentFileBaseName === DUMMY_PATH) {
      attachmentFileContent ??= new ArrayBuffer(0);
      const now = Math.trunc(Date.now());
      attachmentFileStats ??= {
        ctime: now,
        mtime: now,
        size: 0
      };
    }

    const noteFile = getFileOrNull(this.app, params.notePathOrFile);
    const noteFilePath = params.notePathOrFile ? getPath(this.app, params.notePathOrFile) : undefined;
    const oldNoteFilePath = params.oldNotePathOrFile ? getPath(this.app, params.oldNotePathOrFile) : undefined;

    if (attachmentFileBaseName.startsWith(IMPORT_FILES_PREFIX)) {
      attachmentFileBaseName = trimStart(attachmentFileBaseName, IMPORT_FILES_PREFIX);
      shouldSkipGeneratedAttachmentFileName = true;
    }
    if (noteFile && this.pluginSettingsComponent.settings.isPathIgnored(noteFile.path) && this.getAvailablePathForAttachmentsOriginal) {
      return this.getAvailablePathForAttachmentsOriginal(attachmentFileBaseName, params.attachmentFileExtension, noteFile);
    }

    let attachmentPath: string;
    if (!noteFilePath || !isNote(this.app, noteFilePath)) {
      attachmentPath = await getAvailablePathForAttachments({
        app: this.app,
        attachmentFileBaseName,
        attachmentFileExtension: params.attachmentFileExtension,
        notePathOrFile: params.notePathOrFile,
        shouldSkipDuplicateCheck: params.shouldSkipDuplicateCheck ?? false,
        shouldSkipMissingAttachmentFolderCreation: params.shouldSkipMissingAttachmentFolderCreation ?? true
      });
    } else {
      const attachmentFileName = makeFileName(attachmentFileBaseName, params.attachmentFileExtension);
      const attachmentFolderFullPath = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
        actionContext: attachmentPathContextToActionContext(params.context),
        attachmentFileContent,
        attachmentFileName,
        attachmentFileStats,
        notePath: noteFilePath,
        oldNoteFilePath
      });
      let generatedAttachmentFileName: string;
      if (shouldSkipGeneratedAttachmentFileName) {
        generatedAttachmentFileName = attachmentFileName;
      } else {
        const cursorLine = await this.getCursorLine(noteFilePath, params.oldAttachmentPathOrFile);
        const sequenceNumber = await this.attachmentPathManager.getSequenceNumber(noteFilePath, params.oldAttachmentPathOrFile);
        const generatedAttachmentFileBaseName = await this.attachmentPathManager.getGeneratedAttachmentFileBaseName(
          new Substitutions({
            actionContext: attachmentPathContextToActionContext(params.context),
            app: this.app,
            attachmentFileContent,
            attachmentFileStats,
            cursorLine,
            noteFilePath,
            oldNoteFilePath,
            originalAttachmentFileName: attachmentFileName,
            pluginSettingsComponent: this.pluginSettingsComponent,
            sequenceNumber
          })
        );
        generatedAttachmentFileName = makeFileName(generatedAttachmentFileBaseName, params.attachmentFileExtension);
      }
      const generatedAttachmentFileNamePath = join(attachmentFolderFullPath, generatedAttachmentFileName);
      if (params.shouldSkipDuplicateCheck) {
        attachmentPath = generatedAttachmentFileNamePath;
      } else {
        const dir = dirname(generatedAttachmentFileNamePath);
        const generatedAttachmentFileNameBaseName = basename(generatedAttachmentFileNamePath, params.attachmentFileExtension ? `.${params.attachmentFileExtension}` : '');
        attachmentPath = this.app.vault.getAvailablePath(join(dir, generatedAttachmentFileNameBaseName), params.attachmentFileExtension);
      }
    }

    if (!params.shouldSkipMissingAttachmentFolderCreation) {
      const folderPath = parentFolderPath(attachmentPath);
      if (!await this.app.vault.exists(folderPath)) {
        await createFolderSafe(this.app, folderPath);
        if (this.pluginSettingsComponent.settings.emptyFolderBehavior === EmptyFolderBehavior.Keep) {
          await this.app.vault.create(join(folderPath, '.gitkeep'), '');
        }
      }
    }

    return attachmentPath;
  }

  public async saveAttachment(params: AttachmentSaverSaveAttachmentParams): Promise<TFile> {
    let attachmentFileBaseName = params.attachmentFileBaseName;
    let attachmentFileContent = params.attachmentFileContent;
    let attachmentFileExtension = params.attachmentFileExtension;

    const activeNoteFile = this.app.workspace.getActiveFile();
    if (!activeNoteFile || this.pluginSettingsComponent.settings.isPathIgnored(activeNoteFile.path)) {
      return await this.saveAttachmentCore({
        attachmentFileBaseName,
        attachmentFileContent,
        attachmentFileExtension
      });
    }

    let isPastedImage = false;
    const match = PASTED_IMAGE_NAME_REG_EXP.exec(attachmentFileBaseName);
    if (match) {
      const timestampString = ensureNonNullable(match.groups?.['Timestamp']);
      const parsedDate = moment(timestampString, PASTED_IMAGE_DATE_FORMAT);
      if (parsedDate.isValid()) {
        if (moment().diff(parsedDate, 'seconds') < THRESHOLD_IN_SECONDS) {
          isPastedImage = true;
        }
      }
    }

    const convertImageToJpegResult = await this.imageManager.convertToJpeg({
      attachmentFileContent,
      attachmentFileExtension,
      isPastedImage
    });
    attachmentFileExtension = convertImageToJpegResult.attachmentFileExtension;
    attachmentFileContent = convertImageToJpegResult.attachmentFileContent;

    let shouldRename = false;

    switch (this.pluginSettingsComponent.settings.attachmentRenameMode) {
      case AttachmentRenameMode.All:
        shouldRename = true;
        break;
      case AttachmentRenameMode.None:
        break;
      case AttachmentRenameMode.OnlyPastedImages:
        shouldRename = isPastedImage;
        break;
      default:
        throw new Error('Invalid attachment rename mode');
    }

    if (shouldRename) {
      attachmentFileBaseName = await this.attachmentPathManager.getGeneratedAttachmentFileBaseName(
        new Substitutions({
          actionContext: ActionContext.SaveAttachment,
          app: this.app,
          attachmentFileContent,
          attachmentFileStats: this.arrayBufferMap.getFileStats(attachmentFileContent),
          noteFilePath: activeNoteFile.path,
          originalAttachmentFileName: makeFileName(attachmentFileBaseName, attachmentFileExtension),
          pluginSettingsComponent: this.pluginSettingsComponent
        })
      );
    }

    const attachmentFile = await this.saveAttachmentCore({
      attachmentFileBaseName,
      attachmentFileContent,
      attachmentFileExtension
    });
    if (this.pluginSettingsComponent.settings.markdownUrlFormat) {
      const markdownUrl = await new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        app: this.app,
        attachmentFileContent,
        attachmentFileStats: this.arrayBufferMap.getFileStats(attachmentFileContent) ?? undefined,
        generatedAttachmentFileName: attachmentFile.name,
        generatedAttachmentFilePath: attachmentFile.path,
        noteFilePath: activeNoteFile.path,
        originalAttachmentFileName: makeFileName(attachmentFileBaseName, attachmentFileExtension),
        pluginSettingsComponent: this.pluginSettingsComponent
      }).fillTemplate(this.pluginSettingsComponent.settings.markdownUrlFormat);
      this.markdownUrlMap.set(attachmentFile.path, markdownUrl);
    } else {
      this.markdownUrlMap.delete(attachmentFile.path);
    }
    return attachmentFile;
  }

  private async getCursorLine(noteFilePath: string, oldAttachmentPathOrFile: PathOrFile): Promise<number> {
    const oldAttachmentFile = getFileOrNull(this.app, oldAttachmentPathOrFile);
    if (!oldAttachmentFile) {
      return 0;
    }

    const cache = await getCacheSafe(this.app, noteFilePath);
    if (!cache) {
      return 0;
    }

    for (const link of getAllLinks(cache)) {
      if (!isReferenceCache(link)) {
        continue;
      }

      const linkFile = extractLinkFile(this.app, link, noteFilePath);
      if (!linkFile) {
        continue;
      }

      if (linkFile === oldAttachmentFile) {
        return link.position.start.line;
      }
    }

    return 0;
  }

  private async saveAttachmentCore(params: AttachmentSaverSaveAttachmentCoreParams): Promise<TFile> {
    const noteFile = this.app.workspace.getActiveFile();
    const attachmentFileStats = this.arrayBufferMap.getFileStats(params.attachmentFileContent);

    const attachmentPath = await this.getAvailablePathForAttachments({
      attachmentFileBaseName: params.attachmentFileBaseName,
      attachmentFileContent: params.attachmentFileContent,
      attachmentFileExtension: params.attachmentFileExtension,
      attachmentFileStats,
      context: actionContextToAttachmentPathContext(ActionContext.SaveAttachment),
      notePathOrFile: noteFile,
      oldAttachmentPathOrFile: makeFileName(params.attachmentFileBaseName, params.attachmentFileExtension),
      shouldSkipDuplicateCheck: false,
      shouldSkipGeneratedAttachmentFileName: true,
      shouldSkipMissingAttachmentFolderCreation: false
    });

    const imageSize = await this.imageManager.getImageSize({
      content: params.attachmentFileContent,
      extension: params.attachmentFileExtension
    });
    if (imageSize !== null) {
      this.imageSizeMap.set(attachmentPath, imageSize);
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
}
