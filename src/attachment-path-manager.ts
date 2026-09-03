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
import {
  createFolderSafe,
  EmptyFolderBehavior
} from 'obsidian-dev-utils/obsidian/vault';
import {
  basename,
  dirname,
  join,
  makeFileName
} from 'obsidian-dev-utils/path';
import { trimStart } from 'obsidian-dev-utils/string';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { IMPORT_FILES_PREFIX } from './patches/share-receiver-import-files-patch-component.ts';
import { selfWriteRegistry } from './self-write-registry.ts';
import { Substitutions } from './substitutions.ts';
import {
  ActionContext,
  attachmentPathContextToActionContext,
  TemplatePart
} from './token-evaluator-context.ts';
import {
  TokenValidationMode,
  TokenValidator
} from './token-validator.ts';

// eslint-disable-next-line no-template-curly-in-string -- Valid token.
const ORIGINAL_ATTACHMENT_FILE_NAME_TEMPLATE = '${originalAttachmentFileName}';

interface AttachmentPathManagerConstructorParams {
  readonly app: App;
  readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFunction;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
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

interface CursorLineAndSequenceNumber {
  readonly cursorLine: number;
  readonly sequenceNumber: number;
}

type GetAvailablePathForAttachmentsFunction = Vault['getAvailablePathForAttachments'];

interface NoteLinkWalkResult {
  readonly cursorLine: number;
  readonly sequenceNumberByAttachmentPath: Map<string, number>;
}

export class AttachmentPathManager {
  private readonly app: App;
  private readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFunction;
  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: AttachmentPathManagerConstructorParams) {
    this.app = params.app;
    this.getAvailablePathForAttachmentsOriginal = params.getAvailablePathForAttachmentsOriginal;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
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
    let shouldSkipGeneratedAttachmentFileName = this.isGeneratedAttachmentFileNameSkipped(params.context, params.shouldSkipGeneratedAttachmentFileName);
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
        $string: attachmentFileBaseName,
        prefix: IMPORT_FILES_PREFIX
      });
      shouldSkipGeneratedAttachmentFileName = true;
    }
    if (noteFile && this.handedOverSettingsComponent.isPathIgnored(noteFile.path)) {
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
        const { cursorLine, sequenceNumber } = await this.getCursorLineAndSequenceNumber(noteFilePath, params.oldAttachmentPathOrFile);
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
        const directory = dirname(generatedAttachmentFileNamePath);
        const generatedAttachmentFileNameBaseName = basename(generatedAttachmentFileNamePath, params.attachmentFileExtension ? `.${params.attachmentFileExtension}` : '');
        attachmentPath = this.app.vault.getAvailablePath(join(directory, generatedAttachmentFileNameBaseName), params.attachmentFileExtension);
      }
    }

    /*
     * Claim every path this resolver hands out, so the externally-created-attachment handler does not
     * process a file the plugin itself just named. It covers the core save flows that resolve here and
     * then write the path themselves — the audio recorder, a dropped-file import, and the mobile share
     * import, which has ALREADY had its name generated by `ShareReceiverImportFilesPatchComponent` and
     * would otherwise be renamed (and, with `${prompt}`, prompted for) a second time.
     *
     * Claiming a path that never gets written costs nothing: the entry expires, and it is only ever
     * consumed by a creation at exactly that path — which would mean the writer used the name this
     * plugin gave it, and so needs no renaming anyway.
     */
    selfWriteRegistry.register(attachmentPath);

    if (!params.shouldSkipMissingAttachmentFolderCreation) {
      const folderPath = parentFolderPath(attachmentPath);
      if (!await this.app.vault.exists(folderPath)) {
        await createFolderSafe(this.app, folderPath);
        if (this.handedOverSettingsComponent.settings.emptyFolderBehavior === EmptyFolderBehavior.Keep) {
          /*
           * Materialize the Keep placeholder idempotently. On a multi-device sync
           * (iCloud/Git), a peer may have already synced the same `.gitkeep` onto
           * disk in the window between the folder-existence check above and this
           * write. An unconditional `create` would then throw (file already exists)
           * and, worse, overwrite it, re-emitting a change event that feeds a
           * cross-device sync loop (issue #16). Skip the write when the placeholder
           * is already present.
           */
          const gitKeepPath = join(folderPath, '.gitkeep');
          if (!await this.app.vault.exists(gitKeepPath)) {
            selfWriteRegistry.register(gitKeepPath);
            await this.app.vault.create(gitKeepPath, '');
          }
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
    const directory = dirname(generatedAttachmentFileNamePath);
    const generatedAttachmentFileNameBaseName = basename(generatedAttachmentFileNamePath, params.fileExtension ? `.${params.fileExtension}` : '');
    const attachmentPath = this.app.vault.getAvailablePath(join(directory, generatedAttachmentFileNameBaseName), params.fileExtension);

    const folderPath = parentFolderPath(attachmentPath);
    if (!await this.app.vault.exists(folderPath)) {
      await createFolderSafe(this.app, folderPath);
    }

    return attachmentPath;
  }

  public async getGeneratedAttachmentFileBaseName(substitutions: Substitutions): Promise<string> {
    let baseTemplate: string;
    switch (substitutions.actionContext) {
      /*
       * An empty template for an attachment that already exists means "keep the name it has", NOT "fall
       * back to the generated-name template" — that template names a NEWLY CREATED attachment, and running
       * it here renames files the user never asked to rename (and prompts, when it holds a `${prompt}`
       * token). Both of these settings ship empty, so the fallback fired by default.
       */
      case ActionContext.CollectAttachments: {
        baseTemplate = this.pluginSettingsComponent.settings.collectedAttachmentFileName || ORIGINAL_ATTACHMENT_FILE_NAME_TEMPLATE;
        break;
      }
      case ActionContext.RenameNote: {
        baseTemplate = this.pluginSettingsComponent.settings.renamedAttachmentFileName || ORIGINAL_ATTACHMENT_FILE_NAME_TEMPLATE;
        break;
      }
      default: {
        baseTemplate = this.pluginSettingsComponent.settings.generatedAttachmentFileName;
        break;
      }
    }

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
    const { sequenceNumberByAttachmentPath } = await this.walkNoteLinks(noteFilePath, null);
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

  private async getCursorLineAndSequenceNumber(noteFilePath: string, oldAttachmentPathOrFile: PathOrFile): Promise<CursorLineAndSequenceNumber> {
    const oldAttachmentFile = getFileOrNull({
      app: this.app,
      pathOrFile: oldAttachmentPathOrFile
    });
    if (!oldAttachmentFile) {
      return { cursorLine: 0, sequenceNumber: 0 };
    }

    const { cursorLine, sequenceNumberByAttachmentPath } = await this.walkNoteLinks(noteFilePath, oldAttachmentFile);
    return {
      cursorLine,
      sequenceNumber: sequenceNumberByAttachmentPath.get(oldAttachmentFile.path) ?? 0
    };
  }

  private isGeneratedAttachmentFileNameSkipped(context: AttachmentPathContext, shouldSkipGeneratedAttachmentFileName: boolean | undefined): boolean {
    if (shouldSkipGeneratedAttachmentFileName) {
      return true;
    }

    /*
     * A note rename must not rename the attachment when the user turned that off. The setting reaches
     * dev-utils' `RenameDeleteHandlerComponent` only, so a plugin calling `getAttachmentFilePath` directly
     * would otherwise resolve a brand-new name here — and, with a `${prompt}` template, open a modal per
     * renamed note (issue #259 in Advanced Note Composer). Skipping the generated name leaves the file
     * named as it is and moves only its folder.
     */
    return context === AttachmentPathContext.RenameNote && !this.handedOverSettingsComponent.settings.shouldRenameAttachmentFiles;
  }

  private async resolvePathTemplate(params: AttachmentPathManagerResolvePathTemplateParams): Promise<string> {
    const { isFileNamePart, substitutions, template } = params;
    try {
      let resolvedPath = await substitutions.fillTemplate(template, isFileNamePart ? TemplatePart.FileName : TemplatePart.Folder);
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

  /**
   * Walks a note's links once, computing in a single pass both:
   *
   * - `cursorLine` — the start line of the first reference-cache link resolving to `oldAttachmentFile`
   *   (identity match, including a match whose line is `0`); `0` when there is none.
   * - `sequenceNumberByAttachmentPath` — the 1-based numbering of the note's distinct attachments by path.
   *
   * Both `${cursorLine}` and `${sequenceNumber}` are derived from the same `getCacheSafe`/`getLinks`
   * traversal instead of walking the metadata cache twice on the rename/delete hot path.
   */
  private async walkNoteLinks(noteFilePath: string, oldAttachmentFile: null | TFile): Promise<NoteLinkWalkResult> {
    const sequenceNumberByAttachmentPath = new Map<string, number>();
    let cursorLine = 0;
    let isCursorLineFound = false;

    const cache = await getCacheSafe(this.app, noteFilePath);
    if (!cache) {
      return { cursorLine, sequenceNumberByAttachmentPath };
    }

    let sequenceNumber = 1;
    for (const link of getLinks({ cache })) {
      const linkFile = extractLinkFile({
        app: this.app,
        link,
        sourcePathOrFile: noteFilePath
      });

      // Cursor line: the first reference-cache link resolving to the target attachment. Checked before the
      // Note-link filter below, matching the former getCursorLine which never applied that filter.
      if (oldAttachmentFile && !isCursorLineFound && isReferenceCache(link) && linkFile === oldAttachmentFile) {
        cursorLine = link.position.start.line;
        isCursorLineFound = true;
      }

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

    return { cursorLine, sequenceNumberByAttachmentPath };
  }
}

function isRelativePath(path: string): boolean {
  return path === '.' || path.startsWith('./') || path === '..' || path.startsWith('../');
}
