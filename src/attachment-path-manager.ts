import type {
  App,
  FileStats,
  Reference,
  TFile,
  Vault
} from 'obsidian';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import type { PathOrFile } from 'obsidian-dev-utils/obsidian/file-system';

import {
  isReferenceCache,
  parentFolderPath
} from '@obsidian-typings/obsidian-public-latest/implementations';
import { normalizePath } from 'obsidian';
import { printError } from 'obsidian-dev-utils/error';
import {
  AttachmentPathContext,
  DUMMY_PATH,
  getAvailablePathForAttachments
} from 'obsidian-dev-utils/obsidian/attachment-path';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import {
  getFileOrNull,
  getPath,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { appendCodeBlock } from 'obsidian-dev-utils/obsidian/html-element';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { extractLinkFile } from 'obsidian-dev-utils/obsidian/link';
import {
  getCacheSafe,
  getLinks
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

import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { IMPORT_FILES_PREFIX } from './patches/share-receiver-import-files-patch-component.ts';
import { Substitutions } from './substitutions.ts';
import {
  ActionContext,
  attachmentPathContextToActionContext
} from './token-evaluator-context.ts';
import {
  TokenValidationMode,
  TokenValidator
} from './token-validator.ts';

interface AttachmentPathManagerConstructorParams {
  readonly app: App;
  readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFn;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly tokenValidator: TokenValidator;
}

interface AttachmentPathManagerGetAttachmentFolderFullPathForPathParams {
  readonly actionContext: ActionContext;
  readonly attachmentFileContent?: ArrayBuffer | undefined;
  readonly attachmentFileName: string;
  readonly attachmentFileStats?: FileStats | undefined;
  readonly notePath: string;
  readonly oldNoteFilePath?: string | undefined;
  readonly readAttachmentFileContent?: (() => Promise<ArrayBuffer>) | undefined;
}

interface AttachmentPathManagerGetAvailablePathForAttachmentsParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileExtension: string;
  readonly attachmentFileStats?: FileStats | undefined;
  readonly context: AttachmentPathContext;
  readonly notePathOrFile: null | PathOrFile;
  readonly oldAttachmentPathOrFile: PathOrFile;
  readonly oldNotePathOrFile?: PathOrFile | undefined;
  readonly readAttachmentFileContent: (() => Promise<ArrayBuffer>) | null;
  readonly shouldSkipDuplicateCheck?: boolean;
  readonly shouldSkipGeneratedAttachmentFileName?: boolean;
  readonly shouldSkipMissingAttachmentFolderCreation: boolean | undefined;
}

interface AttachmentPathManagerGetDownloadedImagePathParams {
  readonly actionContext: ActionContext;
  readonly downloadedContent: ArrayBuffer;
  readonly fileExtension: string;
  readonly fileName: string;
  readonly noteFilePath: string;
}

interface AttachmentPathManagerGetProperAttachmentPathParams {
  readonly actionContext: ActionContext;
  readonly attachmentFile: TFile;
  readonly noteFilePath: string;
  readonly reference: Reference;
  readonly sequenceNumber: number;
}

interface AttachmentPathManagerResolvePathTemplateParams {
  readonly isFileNamePart: boolean;
  readonly substitutions: Substitutions;
  readonly template: string;
}

type GetAvailablePathForAttachmentsFn = Vault['getAvailablePathForAttachments'];

export class AttachmentPathManager {
  private readonly app: App;
  private readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFn;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: AttachmentPathManagerConstructorParams) {
    this.app = params.app;
    this.getAvailablePathForAttachmentsOriginal = params.getAvailablePathForAttachmentsOriginal;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.tokenValidator = params.tokenValidator;
  }

  public async getAttachmentFolderFullPathForPath(params: AttachmentPathManagerGetAttachmentFolderFullPathForPathParams): Promise<string> {
    return await this.getAttachmentFolderPath(
      new Substitutions({
        actionContext: params.actionContext,
        app: this.app,
        attachmentFileContent: params.attachmentFileContent,
        attachmentFileStats: params.attachmentFileStats,
        noteFilePath: params.notePath,
        oldNoteFilePath: params.oldNoteFilePath,
        originalAttachmentFileName: params.attachmentFileName,
        pluginSettingsComponent: this.pluginSettingsComponent,
        readAttachmentFileContent: params.readAttachmentFileContent,
        tokenValidator: this.tokenValidator
      })
    );
  }

  public async getAvailablePathForAttachments(params: AttachmentPathManagerGetAvailablePathForAttachmentsParams): Promise<string> {
    let attachmentFileBaseName = params.attachmentFileBaseName;
    let attachmentFileStats = params.attachmentFileStats;
    let shouldSkipGeneratedAttachmentFileName = params.shouldSkipGeneratedAttachmentFileName;
    const isDummy = attachmentFileBaseName === DUMMY_PATH;

    if (isDummy) {
      const now = Math.trunc(Date.now());
      attachmentFileStats ??= {
        ctime: now,
        mtime: now,
        size: 0
      };
    }

    const noteFile = getFileOrNull({
      app: this.app,
      pathOrFile: params.notePathOrFile
    });
    const noteFilePath = params.notePathOrFile ? getPath(this.app, params.notePathOrFile) : undefined;
    const oldNoteFilePath = params.oldNotePathOrFile ? getPath(this.app, params.oldNotePathOrFile) : undefined;

    if (attachmentFileBaseName.startsWith(IMPORT_FILES_PREFIX)) {
      attachmentFileBaseName = trimStart({
        prefix: IMPORT_FILES_PREFIX,
        str: attachmentFileBaseName
      });
      shouldSkipGeneratedAttachmentFileName = true;
    }
    if (noteFile && this.pluginSettingsComponent.settings.isPathIgnored(noteFile.path)) {
      return this.getAvailablePathForAttachmentsOriginal(attachmentFileBaseName, params.attachmentFileExtension, noteFile);
    }

    let attachmentPath: string;
    if (!noteFilePath || !isNote(noteFilePath)) {
      attachmentPath = await getAvailablePathForAttachments({
        app: this.app,
        attachmentFileBaseName,
        attachmentFileExtension: params.attachmentFileExtension,
        notePathOrFile: params.notePathOrFile,
        shouldSkipDuplicateCheck: params.shouldSkipDuplicateCheck ?? false,
        shouldSkipMissingAttachmentFolderCreation: params.shouldSkipMissingAttachmentFolderCreation ?? true
      });
    } else {
      const readAttachmentFileContent = params.readAttachmentFileContent ?? undefined;
      const attachmentFileName = makeFileName({
        fileBaseName: attachmentFileBaseName,
        fileExtension: params.attachmentFileExtension
      });
      const attachmentFolderFullPath = await this.getAttachmentFolderFullPathForPath({
        actionContext: attachmentPathContextToActionContext(params.context),
        attachmentFileName,
        attachmentFileStats,
        notePath: noteFilePath,
        oldNoteFilePath,
        readAttachmentFileContent
      });
      let generatedAttachmentFileName: string;
      if (shouldSkipGeneratedAttachmentFileName) {
        generatedAttachmentFileName = attachmentFileName;
      } else {
        const cursorLine = await this.getCursorLine(noteFilePath, params.oldAttachmentPathOrFile);
        const sequenceNumber = await this.getSequenceNumber(noteFilePath, params.oldAttachmentPathOrFile);
        const generatedAttachmentFileBaseName = await this.getGeneratedAttachmentFileBaseName(
          new Substitutions({
            actionContext: attachmentPathContextToActionContext(params.context),
            app: this.app,
            attachmentFileStats,
            cursorLine,
            noteFilePath,
            oldNoteFilePath,
            originalAttachmentFileName: attachmentFileName,
            pluginSettingsComponent: this.pluginSettingsComponent,
            readAttachmentFileContent,
            sequenceNumber,
            tokenValidator: this.tokenValidator
          })
        );
        generatedAttachmentFileName = makeFileName({
          fileBaseName: generatedAttachmentFileBaseName,
          fileExtension: params.attachmentFileExtension
        });
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

  public async getDownloadedImagePath(params: AttachmentPathManagerGetDownloadedImagePathParams): Promise<string> {
    const attachmentFileName = makeFileName({
      fileBaseName: params.fileName,
      fileExtension: params.fileExtension
    });
    const now = Math.trunc(Date.now());
    const attachmentFileStats: FileStats = {
      ctime: now,
      mtime: now,
      size: params.downloadedContent.byteLength
    };

    const generatedAttachmentFileBaseName = await this.getGeneratedAttachmentFileBaseName(
      new Substitutions({
        actionContext: params.actionContext,
        app: this.app,
        attachmentFileContent: params.downloadedContent,
        attachmentFileStats,
        noteFilePath: params.noteFilePath,
        originalAttachmentFileName: attachmentFileName,
        pluginSettingsComponent: this.pluginSettingsComponent,
        tokenValidator: this.tokenValidator
      })
    );
    const generatedAttachmentFileName = makeFileName({
      fileBaseName: generatedAttachmentFileBaseName,
      fileExtension: params.fileExtension
    });

    const attachmentFolderFullPath = await this.getAttachmentFolderFullPathForPath({
      actionContext: params.actionContext,
      attachmentFileContent: params.downloadedContent,
      attachmentFileName: generatedAttachmentFileName,
      attachmentFileStats,
      notePath: params.noteFilePath
    });

    const generatedAttachmentFileNamePath = join(attachmentFolderFullPath, generatedAttachmentFileName);
    const dir = dirname(generatedAttachmentFileNamePath);
    const generatedAttachmentFileNameBaseName = basename(generatedAttachmentFileNamePath, params.fileExtension ? `.${params.fileExtension}` : '');
    const attachmentPath = this.app.vault.getAvailablePath(join(dir, generatedAttachmentFileNameBaseName), params.fileExtension);

    const folderPath = parentFolderPath(attachmentPath);
    if (!await this.app.vault.exists(folderPath)) {
      await createFolderSafe(this.app, folderPath);
    }

    return attachmentPath;
  }

  public async getGeneratedAttachmentFileBaseName(substitutions: Substitutions): Promise<string> {
    let baseTemplate: string;
    switch (substitutions.actionContext) {
      case ActionContext.CollectAttachments:
        baseTemplate = this.pluginSettingsComponent.settings.collectedAttachmentFileName;
        break;
      case ActionContext.RenameNote:
        baseTemplate = this.pluginSettingsComponent.settings.renamedAttachmentFileName;
        break;
      default:
        baseTemplate = this.pluginSettingsComponent.settings.generatedAttachmentFileName;
        break;
    }

    baseTemplate ||= this.pluginSettingsComponent.settings.generatedAttachmentFileName;

    const path = await this.resolvePathTemplate({ isFileNamePart: true, substitutions, template: baseTemplate });
    let validationMessage = await this.tokenValidator.validatePath({
      areTokensAllowed: false,
      path
    });
    if (!validationMessage) {
      const parts = path.split('/');
      const fileName = ensureNonNullable(parts.at(-1));
      // eslint-disable-next-line require-atomic-updates -- Ignore possible race condition.
      validationMessage = await this.tokenValidator.validateFileName({
        areSingleDotsAllowed: false,
        fileName,
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Error
      });
    }
    if (validationMessage) {
      this.pluginNoticeComponent.showNotice(createFragment((f) => {
        f.appendText(t(($) => $.notice.generatedAttachmentFileNameIsInvalid.part1, { path, validationMessage }));
        f.appendText(' ');
        appendCodeBlock(f, t(($) => $.pluginSettingsTab.generatedAttachmentFileName.name));
        f.appendText(' ');
        f.appendText(t(($) => $.notice.generatedAttachmentFileNameIsInvalid.part2));
      }));
      const errorMessage = `Generated attachment file name "${path}" is invalid.\n${validationMessage}\nCheck your 'Generated attachment file name' setting.`;
      console.error(errorMessage, substitutions);
      throw new Error(errorMessage);
    }
    return path;
  }

  public async getProperAttachmentPath(params: AttachmentPathManagerGetProperAttachmentPathParams): Promise<null | string> {
    const attachmentFileContent = await this.app.vault.readBinary(params.attachmentFile);
    const newAttachmentName = this.pluginSettingsComponent.settings.shouldRenameCollectedAttachments
      ? makeFileName({
        fileBaseName: await this.getGeneratedAttachmentFileBaseName(
          new Substitutions({
            actionContext: params.actionContext,
            app: this.app,
            attachmentFileContent,
            attachmentFileStats: params.attachmentFile.stat,
            cursorLine: isReferenceCache(params.reference) ? params.reference.position.start.line : 0,
            noteFilePath: params.noteFilePath,
            originalAttachmentFileName: params.attachmentFile.name,
            pluginSettingsComponent: this.pluginSettingsComponent,
            sequenceNumber: params.sequenceNumber,
            tokenValidator: this.tokenValidator
          })
        ),
        fileExtension: params.attachmentFile.extension
      })
      : params.attachmentFile.name;

    const newAttachmentFolderPath = await this.getAttachmentFolderFullPathForPath({
      actionContext: params.actionContext,
      attachmentFileContent,
      attachmentFileName: newAttachmentName,
      attachmentFileStats: params.attachmentFile.stat,
      notePath: params.noteFilePath
    });
    const newAttachmentPath = join(newAttachmentFolderPath, newAttachmentName);

    if (params.attachmentFile.path === newAttachmentPath) {
      return null;
    }

    return newAttachmentPath;
  }

  /**
   * Builds a map from attachment file path to its 1-based sequence number within the note.
   *
   * The `Collect attachments` command must compute this **before** it moves any attachment: a move
   * rewrites the note's links, which would shift the numbering of the attachments processed later in
   * the same pass. Snapshotting the numbering up front keeps each attachment's `${sequenceNumber}`
   * stable regardless of move order.
   */
  public async getSequenceNumberMap(noteFilePath: string): Promise<Map<string, number>> {
    const sequenceNumberByAttachmentPath = new Map<string, number>();
    const cache = await getCacheSafe(this.app, noteFilePath);
    if (!cache) {
      return sequenceNumberByAttachmentPath;
    }

    let sequenceNumber = 1;
    for (const link of getLinks({ cache })) {
      const linkFile = extractLinkFile({
        app: this.app,
        link,
        sourcePathOrFile: noteFilePath
      });

      // Skip note links (e.g. `![[Note#Section]]` section embeds); they are not attachments.
      // Note embeds must not advance the sequence number; the collector applies the same filter.
      if (this.pluginSettingsComponent.isNoteEx(linkFile)) {
        continue;
      }

      if (linkFile && !sequenceNumberByAttachmentPath.has(linkFile.path)) {
        sequenceNumberByAttachmentPath.set(linkFile.path, sequenceNumber);
      }

      sequenceNumber++;
    }

    return sequenceNumberByAttachmentPath;
  }

  private cleanFilePathPart(part: string): string {
    let cleanPart = part.trimEnd();
    if (cleanPart === '.' || cleanPart === '..') {
      return cleanPart;
    }

    cleanPart = cleanPart.replace(/[\s.]+$/, '');
    cleanPart = this.pluginSettingsComponent.replaceSpecialCharacters(cleanPart);
    return cleanPart;
  }

  private async getAttachmentFolderPath(substitutions: Substitutions): Promise<string> {
    return await this.resolvePathTemplate({ isFileNamePart: false, substitutions, template: this.pluginSettingsComponent.settings.attachmentFolderPath });
  }

  private async getCursorLine(noteFilePath: string, oldAttachmentPathOrFile: PathOrFile): Promise<number> {
    const oldAttachmentFile = getFileOrNull({
      app: this.app,
      pathOrFile: oldAttachmentPathOrFile
    });
    if (!oldAttachmentFile) {
      return 0;
    }

    const cache = await getCacheSafe(this.app, noteFilePath);
    if (!cache) {
      return 0;
    }

    for (const link of getLinks({ cache })) {
      if (!isReferenceCache(link)) {
        continue;
      }

      const linkFile = extractLinkFile({
        app: this.app,
        link,
        sourcePathOrFile: noteFilePath
      });
      if (!linkFile) {
        continue;
      }

      if (linkFile === oldAttachmentFile) {
        return link.position.start.line;
      }
    }

    return 0;
  }

  private async getSequenceNumber(noteFilePath: string, oldAttachmentPathOrFile: PathOrFile): Promise<number> {
    const oldAttachmentFile = getFileOrNull({
      app: this.app,
      pathOrFile: oldAttachmentPathOrFile
    });
    if (!oldAttachmentFile) {
      return 0;
    }

    const sequenceNumberByAttachmentPath = await this.getSequenceNumberMap(noteFilePath);
    return sequenceNumberByAttachmentPath.get(oldAttachmentFile.path) ?? 0;
  }

  private async resolvePathTemplate(params: AttachmentPathManagerResolvePathTemplateParams): Promise<string> {
    const { isFileNamePart, substitutions, template } = params;
    try {
      let resolvedPath = await substitutions.fillTemplate(template);
      const resolvedPathParts = resolvedPath.split('/').map((part) => this.cleanFilePathPart(part));
      resolvedPath = resolvedPathParts.join('/');

      const validationError = await this.tokenValidator.validatePath({
        areTokensAllowed: false,
        path: resolvedPath
      });
      if (validationError) {
        throw new Error(`Resolved path ${resolvedPath} is invalid: ${validationError}`);
      }

      if (!isFileNamePart) {
        if (isRelativePath(resolvedPath)) {
          resolvedPath = join(substitutions.noteFolderPath, resolvedPath);
        }

        resolvedPath = normalizePath(resolvedPath);
      }

      if (resolvedPath === '.') {
        resolvedPath = '';
      }

      if (isRelativePath(resolvedPath)) {
        throw new Error('Resolved path should be absolute');
      }

      return resolvedPath;
    } catch (error) {
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.couldNotResolveTemplatePath, { template }));
      console.error('Could not resolve template path', {
        substitutions,
        template
      });
      printError(error);
      throw error;
    }
  }
}

function isRelativePath(path: string): boolean {
  return path === '.' || path.startsWith('./') || path === '..' || path.startsWith('../');
}
