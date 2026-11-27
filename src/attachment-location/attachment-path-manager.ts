import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { PathOrFile } from '@mnaoumov/obsidian-lib/file-system';
import type {
  App,
  CachedMetadata,
  FileStats,
  Reference,
  TFile,
  Vault
} from 'obsidian';

import {
  AttachmentPathContext,
  DUMMY_PATH,
  getAvailablePathForAttachments
} from '@mnaoumov/obsidian-lib/attachment-path';
import {
  getAbstractFileOrNull,
  getFileOrNull,
  getPath,
  isNote
} from '@mnaoumov/obsidian-lib/file-system';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { extractReferenceFile } from '@mnaoumov/obsidian-lib/link';
import {
  getCacheSafe,
  getReferences
} from '@mnaoumov/obsidian-lib/metadata-cache';
import {
  createFolderSafe,
  EmptyFolderBehavior
} from '@mnaoumov/obsidian-lib/vault';
import { printError } from '@mnaoumov/typescript-lib/error';
import {
  basename,
  dirname,
  extname,
  join,
  makeFileName
} from '@mnaoumov/typescript-lib/path';
import { escapeRegExp } from '@mnaoumov/typescript-lib/reg-exp';
import { trimStart } from '@mnaoumov/typescript-lib/string';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';
import {
  isReferenceCache,
  parentFolderPath
} from '@obsidian-typings/obsidian-public-latest/implementations';
import {
  FileSystemAdapter,
  normalizePath,
  Platform
} from 'obsidian';

import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { NewAttachmentOperation } from '../attachment-saving/new-attachment-operation.ts';
import type { OriginalAttachmentNamesComponent } from '../original-attachment-names/original-attachment-names-component.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentFileNameParams } from '../tokens/substitutions.ts';

import { isImageExtension } from '../attachment-saving/image-mime-types.ts';
import { selfWriteRegistry } from '../externally-created-attachments/self-write-registry.ts';
import {
  codeNode,
  translateFragment
} from '../i18n/translate-fragment.ts';
import { AttachmentOperation } from '../settings/attachment-operation.ts';
import {
  formatString,
  stringFormatSchema
} from '../tokens/base/string-token-base.ts';
import { Substitutions } from '../tokens/substitutions.ts';
import {
  ActionContext,
  attachmentPathContextToActionContext,
  isCollectActionContext,
  TemplatePart
} from '../tokens/token-evaluator-context.ts';
import {
  parseTokenFormat,
  scanTokens
} from '../tokens/token-parser.ts';
import {
  TokenValidationMode,
  TokenValidator
} from '../tokens/token-validator.ts';
import { fitFileBaseName } from './file-name-length-limit.ts';
import { doesFolderExist } from './folder-existence.ts';
import { findIdenticalAttachmentFile } from './identical-attachment.ts';
import {
  getShareImportOriginalFileName,
  IMPORT_FILES_PREFIX
} from './share-receiver-import-files-patch-component.ts';

/*
 * What an empty collect or note-rename template means: the name the attachment has NOW. Not
 * `{{originalAttachmentFileName}}`, which reads the stored arrival name: a note rename would then move every
 * attachment back to the name it arrived with (issue #104), and an alias that matched that arrival name would be
 * refreshed while its neighbors kept theirs.
 */
const CURRENT_ATTACHMENT_FILE_NAME_TEMPLATE = '{{attachmentFileName}}';
const ORIGINAL_ATTACHMENT_FILE_NAME_TOKEN = 'originalAttachmentFileName'.toLowerCase();
const ORIGINAL_ATTACHMENT_FILE_EXTENSION_TOKEN = 'originalAttachmentFileExtension'.toLowerCase();
const ATTACHMENT_FILE_NAME_TOKEN = 'attachmentFileName'.toLowerCase();
const ATTACHMENT_FILE_EXTENSION_TOKEN = 'attachmentFileExtension'.toLowerCase();
const SYNCHRONOUS_INSERTED_LINK_TEXT_TOKENS: ReadonlySet<string> = new Set([
  ATTACHMENT_FILE_EXTENSION_TOKEN,
  ATTACHMENT_FILE_NAME_TOKEN,
  ORIGINAL_ATTACHMENT_FILE_EXTENSION_TOKEN,
  ORIGINAL_ATTACHMENT_FILE_NAME_TOKEN
]);
const MAX_INSERTED_LINK_TEXTS = 100;
const INSERTED_LINK_TEXT_LIFETIME_IN_MILLISECONDS = 60_000;
const MAX_NOTE_REFERENCE_RESOLUTIONS = 100;

/**
 * What the settings preview shows where `{{prompt}}` would ask: the token itself, since the answer is the user's.
 */
const PROMPT_TOKEN_PREVIEW = '{{prompt}}';

interface AttachmentPathManagerCleanKeptFileBaseNameParams {
  readonly fileBaseName: string;
  readonly isGeneratedByShareReceiver: boolean;
  readonly shouldReplace: boolean | undefined;
}

interface AttachmentPathManagerConstructorParams {
  readonly app: App;
  readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFunction;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly tokenValidator: TokenValidator;
}

interface AttachmentPathManagerFitFileBaseNameParams {
  readonly fileBaseName: string;
  readonly fileExtension: string;
  readonly folderPath: string;
  readonly shouldNotify: boolean;
}

interface AttachmentPathManagerGetAttachmentFolderFullPathForPathParams {
  readonly actionContext: ActionContext;
  readonly attachmentFileContent?: ArrayBuffer | undefined;
  readonly attachmentFileName: string;
  readonly attachmentFileStats?: FileStats | undefined;
  readonly newAttachmentOperation?: NewAttachmentOperation | undefined;
  readonly notePath: string;
  readonly oldNoteFilePath?: string | undefined;
  readonly originalAttachmentFileNameParams?: OriginalAttachmentFileNameParams | undefined;
  readonly readAttachmentFileContent?: (() => Promise<ArrayBuffer>) | undefined;
}

interface AttachmentPathManagerGetAvailablePathForAttachmentsParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileExtension: string;
  readonly attachmentFileStats?: FileStats | undefined;
  readonly context: AttachmentPathContext;

  /**
   * How a NEW attachment arrived, which picks its operation's folder and file name templates. Left out by every
   * caller that does not know, which then gets the defaults.
   */
  readonly newAttachmentOperation?: NewAttachmentOperation | undefined;
  readonly notePathOrFile: null | PathOrFile;
  readonly oldAttachmentPathOrFile: PathOrFile;
  readonly oldNotePathOrFile?: PathOrFile | undefined;

  /**
   * The name a NEW attachment arrives with, extension included, when it differs from the name being placed — a
   * paste the saver has already renamed. Defaults to that name.
   */
  readonly originalAttachmentFileName?: string | undefined;
  readonly readAttachmentFileContent: (() => Promise<ArrayBuffer>) | null;
  readonly shouldReplaceSpecialCharactersInKeptFileName?: boolean;
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

interface AttachmentPathManagerGetInsertedLinkTextParams {
  readonly attachmentFile: TFile;
  readonly notePath: string;
}

interface AttachmentPathManagerGetProperAttachmentPathParams {
  readonly actionContext: ActionContext;
  readonly attachmentFile: TFile;
  readonly noteFilePath: string;
  readonly reference: Reference;
  readonly sequenceNumber: number;
}

interface AttachmentPathManagerGetRenamedAttachmentPathParams {
  readonly attachmentFile: TFile;
  readonly cursorLine: number;
  readonly noteFilePath: string;
  readonly sequenceNumber: number;
}

type AttachmentPathManagerIsQueryParams = Pick<AttachmentPathManagerGetAvailablePathForAttachmentsParams, 'shouldSkipDuplicateCheck' | 'shouldSkipMissingAttachmentFolderCreation'>;

interface AttachmentPathManagerPrepareInsertedLinkTextParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileStats: FileStats | undefined;
  readonly attachmentPath: string;
  readonly noteFilePath: string | undefined;
  readonly originalAttachmentFileNameParams: OriginalAttachmentFileNameParams;
  readonly params: AttachmentPathManagerGetAvailablePathForAttachmentsParams;
}

interface AttachmentPathManagerPreviewNewAttachmentPathParams {
  readonly attachmentFileName: string;
  readonly newAttachmentOperation?: NewAttachmentOperation | undefined;
  readonly noteFilePath: string;
}

interface AttachmentPathManagerResolveOriginalAttachmentFileNameParams {
  readonly attachmentFileBaseName: string;
  readonly isGeneratedByShareReceiver: boolean;
  readonly params: AttachmentPathManagerGetAvailablePathForAttachmentsParams;
}

interface AttachmentPathManagerResolvePathTemplateParams {
  readonly isFileNamePart: boolean;
  readonly substitutions: Substitutions;
  readonly template: string;
}

interface AttachmentPathManagerTakeInsertedLinkTextParams {
  readonly attachmentPath: string;
  readonly notePath: string;
}

interface CursorLineAndSequenceNumber {
  readonly cursorLine: number;
  readonly sequenceNumber: number;
}

type GetAvailablePathForAttachmentsFunction = Vault['getAvailablePathForAttachments'];

interface InsertedLinkTextEntry {
  readonly expiresAt: number;
  readonly notePath: string;
  readonly template: string;
  readonly text: string;
}

interface NoteLinkWalkResult {
  readonly cursorLine: number;
  readonly sequenceNumberByAttachmentPath: Map<string, number>;
}

interface ResolvedNoteReference {
  readonly linkFile: null | TFile;
  readonly reference: Reference;
}

interface ResolvedOriginalAttachmentFileName {
  /**
   * The name a NEW attachment arrives with. Unused for an existing one.
   */
  readonly arrivalFileName: string;

  /**
   * The attachment asked about, when it already exists.
   */
  readonly existingAttachmentFile: null | TFile;
  readonly originalAttachmentFileNameParams: OriginalAttachmentFileNameParams;
}

export class AttachmentPathManager {
  /**
   * The arrival names `{{originalAttachmentFileName}}` reads.
   */
  public readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly app: App;
  private readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFunction;
  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly insertedLinkTexts = new Map<string, InsertedLinkTextEntry>();
  private readonly noteReferenceResolutions = new Map<string, readonly ResolvedNoteReference[]>();
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: AttachmentPathManagerConstructorParams) {
    this.app = params.app;
    this.getAvailablePathForAttachmentsOriginal = params.getAvailablePathForAttachmentsOriginal;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
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
        newAttachmentOperation: params.newAttachmentOperation,
        noteFilePath: params.notePath,
        oldNoteFilePath: params.oldNoteFilePath,
        ...params.originalAttachmentFileNameParams,
        attachmentFileName: params.attachmentFileName,
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

    let isGeneratedByShareReceiver = false;
    if (attachmentFileBaseName.startsWith(IMPORT_FILES_PREFIX)) {
      attachmentFileBaseName = trimStart({
        $string: attachmentFileBaseName,
        prefix: IMPORT_FILES_PREFIX
      });
      shouldSkipGeneratedAttachmentFileName = true;
      isGeneratedByShareReceiver = true;
    }

    const resolvedOriginalAttachmentFileName = this.resolveOriginalAttachmentFileName({
      attachmentFileBaseName,
      isGeneratedByShareReceiver,
      params
    });
    const { originalAttachmentFileNameParams } = resolvedOriginalAttachmentFileName;
    if (noteFile && this.handedOverSettingsComponent.isPathIgnored(noteFile.path)) {
      return this.getAvailablePathForAttachmentsOriginal(attachmentFileBaseName, params.attachmentFileExtension, noteFile);
    }

    attachmentFileBaseName = this.cleanKeptFileBaseName({
      fileBaseName: attachmentFileBaseName,
      isGeneratedByShareReceiver,
      shouldReplace: params.shouldReplaceSpecialCharactersInKeptFileName
    });

    let attachmentPath: string;
    // Plain `isNote`, not `isNoteEx`, on purpose: a drawing the user treats as an attachment still OWNS an
    // attachment folder, so an image pasted into it follows the configured template rather than Obsidian's
    // default location. Every other site asks `isNoteEx`; this one disagreeing is the decision, not a defect.
    if (noteFilePath && isNote(noteFilePath)) {
      const readAttachmentFileContent = params.readAttachmentFileContent ?? undefined;
      const attachmentFileName = makeFileName({
        fileBaseName: attachmentFileBaseName,
        fileExtension: params.attachmentFileExtension
      });
      const attachmentFolderFullPath = await this.getAttachmentFolderFullPathForPath({
        actionContext: attachmentPathContextToActionContext(params.context),
        attachmentFileName,
        attachmentFileStats,
        newAttachmentOperation: params.newAttachmentOperation,
        notePath: noteFilePath,
        oldNoteFilePath,
        originalAttachmentFileNameParams,
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
            newAttachmentOperation: params.newAttachmentOperation,
            noteFilePath,
            oldNoteFilePath,
            ...originalAttachmentFileNameParams,
            attachmentFileName,
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
      const directory = dirname(generatedAttachmentFileNamePath);
      const unfittedBaseName = basename(generatedAttachmentFileNamePath, params.attachmentFileExtension ? `.${params.attachmentFileExtension}` : '');
      const generatedAttachmentFileNameBaseName = this.fitFileBaseName({
        fileBaseName: unfittedBaseName,
        fileExtension: params.attachmentFileExtension,
        folderPath: directory,
        shouldNotify: !this.isQuery(params)
      });
      if (params.shouldSkipDuplicateCheck) {
        attachmentPath = generatedAttachmentFileNameBaseName === unfittedBaseName ? generatedAttachmentFileNamePath : join(
          directory,
          makeFileName({
            fileBaseName: generatedAttachmentFileNameBaseName,
            fileExtension: params.attachmentFileExtension
          })
        );
      } else {
        attachmentPath = this.app.vault.getAvailablePath(join(directory, generatedAttachmentFileNameBaseName), params.attachmentFileExtension);
      }
    } else {
      attachmentPath = await getAvailablePathForAttachments({
        app: this.app,
        attachmentFileBaseName,
        attachmentFileExtension: params.attachmentFileExtension,
        notePathOrFile: params.notePathOrFile,
        shouldSkipDuplicateCheck: params.shouldSkipDuplicateCheck ?? false,
        shouldSkipMissingAttachmentFolderCreation: params.shouldSkipMissingAttachmentFolderCreation ?? true
      });
    }

    /*
     * Claim every path this resolver hands out, so the externally-created-attachment handler does not
     * process a file the plugin itself just named. It covers the core save flows that resolve here and
     * then write the path themselves — the audio recorder, a dropped-file import, and the mobile share
     * import, which has ALREADY had its name generated by `ShareReceiverImportFilesPatchComponent` and
     * would otherwise be renamed (and, with `{{prompt}}`, prompted for) a second time.
     *
     * Claiming a path that never gets written costs nothing: the entry expires, and it is only ever
     * consumed by a creation at exactly that path — which would mean the writer used the name this
     * plugin gave it, and so needs no renaming anyway.
     *
     * Not when the name was the CALLER's, though. `VaultGetAvailablePathForAttachmentsPatchComponent` hands
     * out paths whose file name it passed through untouched, so it downgrades this claim to one that holds only
     * while core Obsidian is the writer (issue #65).
     *
     * Not for a QUERY either: a caller that skips both the duplicate check and the folder creation is asking where
     * an attachment belongs, and the answer may be occupied, under a folder that does not exist. Nothing is written
     * there, so it claims nothing, expects no arrival and prepares no link text. A vault-wide audit asks this once
     * per reference, and each of those three would otherwise pile up a minute's worth of entries.
     */
    if (this.isQuery(params)) {
      return attachmentPath;
    }

    selfWriteRegistry.register(attachmentPath);

    this.expectArrivalOfNewAttachment(attachmentPath, resolvedOriginalAttachmentFileName);

    if (!params.shouldSkipMissingAttachmentFolderCreation) {
      await this.ensureAttachmentFolder(parentFolderPath(attachmentPath));
    }

    await this.prepareInsertedLinkText({ attachmentFileBaseName, attachmentFileStats, attachmentPath, noteFilePath, originalAttachmentFileNameParams, params });
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
    const generatedAttachmentFileNameBaseName = this.fitFileBaseName({
      fileBaseName: basename(generatedAttachmentFileNamePath, params.fileExtension ? `.${params.fileExtension}` : ''),
      fileExtension: params.fileExtension,
      folderPath: directory,
      shouldNotify: true
    });
    const attachmentPath = this.app.vault.getAvailablePath(join(directory, generatedAttachmentFileNameBaseName), params.fileExtension);
    this.originalAttachmentNamesComponent.expectArrival(attachmentPath, attachmentFileName);

    const folderPath = parentFolderPath(attachmentPath);
    if (!await doesFolderExist(this.app, folderPath)) {
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
       * it here renames files the user never asked to rename (and prompts, when it holds a `{{prompt}}`
       * token). Both of these settings ship empty, so the fallback fired by default.
       */
      case ActionContext.CollectAttachments:
      case ActionContext.PlanCollectAttachments: {
        baseTemplate = this.pluginSettingsComponent.settings.getOperationFileName(AttachmentOperation.Collect) || CURRENT_ATTACHMENT_FILE_NAME_TEMPLATE;
        break;
      }
      /*
       * The one existing-attachment context whose empty template falls back to the GENERATED name: renaming is the
       * whole point of the command that uses it, so keeping the name would leave the command doing nothing until it is configured.
       */
      case ActionContext.RenameAttachments: {
        baseTemplate = this.pluginSettingsComponent.settings.getOperationFileName(AttachmentOperation.RenameCommand) || this.pluginSettingsComponent.settings.generatedAttachmentFileName;
        break;
      }
      case ActionContext.RenameNote: {
        baseTemplate = this.pluginSettingsComponent.settings.getOperationFileName(AttachmentOperation.NoteRename) || CURRENT_ATTACHMENT_FILE_NAME_TEMPLATE;
        break;
      }
      /*
       * A new attachment: its operation's template when it has one (a pasted screenshot, a pasted or dropped file, or
       * an insert with neither), otherwise the generated-name template every new attachment shares.
       */
      default: {
        const settings = this.pluginSettingsComponent.settings;
        baseTemplate = (substitutions.newAttachmentOperation === undefined ? '' : settings.getNewAttachmentFileName(substitutions.newAttachmentOperation))
          || settings.generatedAttachmentFileName;
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

      validationMessage = await this.tokenValidator.validateFileName({
        areSingleDotsAllowed: false,
        fileName,
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Error
      });
    }
    if (validationMessage) {
      if (substitutions.actionContext === ActionContext.PreviewTemplates) {
        // The settings preview shows the message itself, on every keystroke, so it must not raise a notice too.
        throw new Error(validationMessage);
      }
      this.pluginNoticeComponent.showNotice(translateFragment(
        ($) => $.notice.generatedAttachmentFileNameIsInvalid,
        { settingName: codeNode(t(($) => $.pluginSettingsTab.generatedAttachmentFileName.name)) },
        { path, validationMessage }
      ));
      const errorMessage = `Generated attachment file name "${path}" is invalid.\n${validationMessage}\nCheck your 'Generated attachment file name' setting.`;
      console.error(errorMessage, substitutions);
      throw new Error(errorMessage);
    }
    return path;
  }

  public getInsertedLinkText(params: AttachmentPathManagerGetInsertedLinkTextParams): null | string {
    const prepared = this.takeInsertedLinkText({ attachmentPath: params.attachmentFile.path, notePath: params.notePath });
    if (prepared !== null) {
      return prepared;
    }
    // Existing files have no asynchronous import in flight. The current-name tokens read the file and the
    // original-name tokens read the durable store, both synchronously, including after collect/rename; other
    // templates require an import preparation.
    const template = this.pluginSettingsComponent.settings.insertedLinkText;
    const tokens = scanTokens(template).map((token) => ({ ...token, token: token.token.toLowerCase() }));
    if (tokens.some((token) => !SYNCHRONOUS_INSERTED_LINK_TEXT_TOKENS.has(token.token))) {
      return null;
    }
    let originalName = params.attachmentFile.name;
    if (tokens.some((token) => token.token === ORIGINAL_ATTACHMENT_FILE_NAME_TOKEN || token.token === ORIGINAL_ATTACHMENT_FILE_EXTENSION_TOKEN)) {
      const originalNameParams = this.getOriginalAttachmentFileNameParams(params.attachmentFile, ActionContext.Unknown);
      originalName = originalNameParams.originalAttachmentFileName ?? originalName;
      originalNameParams.onOriginalAttachmentFileNameUnknown?.();
    }
    const originalExtension = extname(originalName);
    function getValue(token: string): string {
      switch (token) {
        case ATTACHMENT_FILE_EXTENSION_TOKEN: {
          return params.attachmentFile.extension;
        }
        case ATTACHMENT_FILE_NAME_TOKEN: {
          return params.attachmentFile.basename;
        }
        case ORIGINAL_ATTACHMENT_FILE_EXTENSION_TOKEN: {
          return originalExtension.slice(1);
        }
        default: {
          return basename(originalName, originalExtension);
        }
      }
    }
    let text = '';
    let offset = 0;
    for (const token of tokens) {
      text += template.slice(offset, token.start) + formatString(getValue(token.token), stringFormatSchema.parse(parseTokenFormat(token) ?? {}));
      offset = token.end;
    }
    return text + template.slice(offset) || null;
  }

  /**
   * What a template reads as the original name of an attachment that already exists: the arrival name on record,
   * or, when there is none, a report that its current name stood in.
   *
   * @param attachmentFile - The attachment.
   * @param actionContext - The action the name is needed for.
   * @returns The parameters to hand {@link Substitutions}.
   */
  public getOriginalAttachmentFileNameParams(attachmentFile: TFile, actionContext: ActionContext): OriginalAttachmentFileNameParams {
    const originalAttachmentFileName = this.originalAttachmentNamesComponent.get(attachmentFile.path);
    if (originalAttachmentFileName !== null) {
      return { originalAttachmentFileName };
    }

    return {
      onOriginalAttachmentFileNameUnknown: (): void => {
        this.originalAttachmentNamesComponent.reportUnknown({
          actionContext,
          currentFileName: attachmentFile.name,
          path: attachmentFile.path
        });
      }
    };
  }

  public async getProperAttachmentPath(params: AttachmentPathManagerGetProperAttachmentPathParams): Promise<null | string> {
    const attachmentFileContent = await this.app.vault.readBinary(params.attachmentFile);
    const originalAttachmentFileNameParams = this.getOriginalAttachmentFileNameParams(params.attachmentFile, params.actionContext);
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
            ...originalAttachmentFileNameParams,
            attachmentFileName: params.attachmentFile.name,
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
      notePath: params.noteFilePath,
      originalAttachmentFileNameParams
    });
    const newAttachmentPath = join(newAttachmentFolderPath, newAttachmentName);

    if (params.attachmentFile.path === newAttachmentPath) {
      return null;
    }

    /*
     * A file parked beside an IDENTICAL one is exactly the duplicate `Deduplicate identical attachments`
     * exists to remove (discussion #96), so it is not left where it is. Merging it leaves nothing parked,
     * which keeps the endless-rename loop the parked check guards against closed.
     */
    if (
      this.isParkedBesideProperPath(params.attachmentFile, newAttachmentPath) && !await findIdenticalAttachmentFile({
        app: this.app,
        attachmentPathOrFile: params.attachmentFile,
        destinationPath: newAttachmentPath,
        pluginSettingsComponent: this.pluginSettingsComponent
      })
    ) {
      return null;
    }

    return newAttachmentPath;
  }

  /**
   * Where `Rename attachments in current note` puts an attachment: its own folder, under the name the rename template
   * gives it for this note.
   *
   * The folder never changes, which is what tells this command apart from collecting. A name already taken by another
   * file gets the duplicate-name suffix, and an attachment already parked under that suffix beside its taken name stays
   * put, so a second run over an unchanged note renames nothing.
   *
   * @param params - The attachment, its note, and its place in the note.
   * @returns The new path, or `null` when the attachment already has its name.
   */
  public async getRenamedAttachmentPath(params: AttachmentPathManagerGetRenamedAttachmentPathParams): Promise<null | string> {
    const attachmentFile = params.attachmentFile;
    const newAttachmentFileBaseName = await this.getGeneratedAttachmentFileBaseName(
      new Substitutions({
        actionContext: ActionContext.RenameAttachments,
        app: this.app,
        attachmentFileStats: attachmentFile.stat,
        cursorLine: params.cursorLine,
        noteFilePath: params.noteFilePath,
        ...this.getOriginalAttachmentFileNameParams(attachmentFile, ActionContext.RenameAttachments),
        attachmentFileName: attachmentFile.name,
        pluginSettingsComponent: this.pluginSettingsComponent,
        readAttachmentFileContent: (): Promise<ArrayBuffer> => this.app.vault.readBinary(attachmentFile),
        sequenceNumber: params.sequenceNumber,
        tokenValidator: this.tokenValidator
      })
    );

    const folderPath = dirname(attachmentFile.path);
    // A template may hold a `/`, which names a subfolder in the generated-name template; here only the name is used.
    const newAttachmentFileName = makeFileName({
      fileBaseName: this.fitFileBaseName({
        fileBaseName: basename(newAttachmentFileBaseName),
        fileExtension: attachmentFile.extension,
        folderPath,
        shouldNotify: true
      }),
      fileExtension: attachmentFile.extension
    });
    const properPath = join(folderPath, newAttachmentFileName);
    if (properPath === attachmentFile.path || this.isParkedBesideProperPath(attachmentFile, properPath)) {
      return null;
    }

    // A change of case alone is a rename of this very file, so the name is not taken.
    if (properPath.toLowerCase() === attachmentFile.path.toLowerCase()) {
      return properPath;
    }

    return this.app.vault.getAvailablePath(join(folderPath, basename(newAttachmentFileName, `.${attachmentFile.extension}`)), attachmentFile.extension);
  }

  public async getSequenceNumberMap(noteFilePath: string): Promise<Map<string, number>> {
    const { sequenceNumberByAttachmentPath } = await this.walkNoteLinks(noteFilePath, null);
    return sequenceNumberByAttachmentPath;
  }

  /**
   * Forgets every remembered link resolution. A file appearing, disappearing or moving can change what any link
   * resolves to, and a note edit replaces its cache, so the plugin calls this on each such vault and metadata event.
   */
  public invalidateNoteReferenceResolutions(): void {
    this.noteReferenceResolutions.clear();
  }

  /**
   * Builds a map from attachment file path to its 1-based sequence number within the note.
   *
   * The `Collect attachments` command must compute this **before** it moves any attachment: a move
   * rewrites the note's links, which would shift the numbering of the attachments processed later in
   * the same pass. Snapshotting the numbering up front keeps each attachment's `{{sequenceNumber}}`
   * stable regardless of move order.
   */
  /**
   * Where a new attachment of the note would be saved, for the settings tab's live preview.
   *
   * The same folder and file name templates a new attachment gets, resolved under
   * {@link ActionContext.PreviewTemplates}: nothing is asked, reported, claimed or created, and no duplicate check
   * runs, because the preview is recomputed on every keystroke and only shows what the templates produce. The
   * placeholder `{{prompt}}` answers with is shown as the token itself.
   *
   * @param params - The note, the incoming file name, and how it arrives.
   * @returns The attachment path.
   * @throws When a template cannot be resolved; the error says why.
   */
  public async previewNewAttachmentPath(params: AttachmentPathManagerPreviewNewAttachmentPathParams): Promise<string> {
    const now = Math.trunc(Date.now());
    const attachmentFileStats: FileStats = { ctime: now, mtime: now, size: 0 };
    const extension = extname(params.attachmentFileName);
    const attachmentFileExtension = extension.slice(1);
    const createSubstitutions = (): Substitutions =>
      new Substitutions({
        actionContext: ActionContext.PreviewTemplates,
        app: this.app,
        attachmentFileName: params.attachmentFileName,
        attachmentFileStats,
        newAttachmentOperation: params.newAttachmentOperation,
        noteFilePath: params.noteFilePath,
        originalAttachmentFileName: params.attachmentFileName,
        pluginSettingsComponent: this.pluginSettingsComponent,
        // The first attachment of the note, so `{{sequenceNumber}}` previews as it would number one.
        sequenceNumber: 1,
        tokenValidator: this.tokenValidator
      });
    const folderPath = await this.getAttachmentFolderPath(createSubstitutions());
    const fileBaseName = await this.getGeneratedAttachmentFileBaseName(createSubstitutions());
    const unfittedPath = join(folderPath, makeFileName({ fileBaseName, fileExtension: attachmentFileExtension }));
    const directory = dirname(unfittedPath);
    const fittedBaseName = this.fitFileBaseName({
      fileBaseName: basename(unfittedPath, extension),
      fileExtension: attachmentFileExtension,
      folderPath: directory,
      shouldNotify: false
    });
    const path = join(directory, makeFileName({ fileBaseName: fittedBaseName, fileExtension: attachmentFileExtension }));
    return path.replaceAll(DUMMY_PATH, () => PROMPT_TOKEN_PREVIEW);
  }

  public takeInsertedLinkText(params: AttachmentPathManagerTakeInsertedLinkTextParams): null | string {
    const entry = this.insertedLinkTexts.get(params.attachmentPath);
    if (!entry || entry.expiresAt < Date.now() || entry.notePath !== params.notePath || entry.template !== this.pluginSettingsComponent.settings.insertedLinkText) {
      return null;
    }
    this.insertedLinkTexts.delete(params.attachmentPath);
    return entry.text || null;
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

  /**
   * Replaces special characters in the name a new attachment keeps.
   *
   * Such a name (a file dropped under `Only pasted images`, or one imported through the patched
   * `getAvailablePathForAttachments`) never meets the template, which is where special characters are otherwise
   * replaced. Left alone, a `#` or `^` in it breaks the link to the attachment
   * (https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/141). A name that would clean to
   * nothing is kept, since an attachment needs a name more than it needs a clean one.
   *
   * The share-sheet import's name is already generated, so it is not a kept one.
   *
   * @param params - The name the attachment arrived with, and whether it is a kept one.
   * @returns The name to use.
   */
  private cleanKeptFileBaseName(params: AttachmentPathManagerCleanKeptFileBaseNameParams): string {
    return !params.shouldReplace || params.isGeneratedByShareReceiver ? params.fileBaseName : this.pluginSettingsComponent.replaceSpecialCharacters(params.fileBaseName) || params.fileBaseName;
  }

  private async ensureAttachmentFolder(folderPath: string): Promise<void> {
    if (await doesFolderExist(this.app, folderPath)) {
      return;
    }

    await createFolderSafe(this.app, folderPath);
    if (this.handedOverSettingsComponent.settings.emptyFolderBehavior !== EmptyFolderBehavior.Keep) {
      return;
    }

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
    if (await this.app.vault.exists(gitKeepPath)) {
      return;
    }

    selfWriteRegistry.register(gitKeepPath);
    await this.app.vault.create(gitKeepPath, '');
  }

  /**
   * Waits for a NEW attachment to be created at the path handed out, so its arrival name is recorded then. A dry
   * resolution never writes the path, and the expectation expires on its own. An existing attachment already has its
   * record, which follows it through the rename.
   *
   * @param attachmentPath - The path handed out.
   * @param resolvedOriginalAttachmentFileName - What the request was resolved to.
   */
  private expectArrivalOfNewAttachment(attachmentPath: string, resolvedOriginalAttachmentFileName: ResolvedOriginalAttachmentFileName): void {
    if (!resolvedOriginalAttachmentFileName.existingAttachmentFile) {
      this.originalAttachmentNamesComponent.expectArrival(attachmentPath, resolvedOriginalAttachmentFileName.arrivalFileName);
    }
  }

  /**
   * Shortens a name the file system would refuse, or would accept but leave unreadable to Obsidian (issue #108), and
   * says so: a template such as `{{heading}}` can grow past either limit without the user noticing.
   *
   * @param params - The name, its folder, and whether a shortening is reported.
   * @returns The base name to use.
   */
  private fitFileBaseName(params: AttachmentPathManagerFitFileBaseNameParams): string {
    // Only Windows bounds the whole path, so only there is the vault's own path needed.
    const isWindows = Platform.isWin;
    const adapter = isWindows ? this.app.vault.adapter : null;
    const result = fitFileBaseName({
      absoluteVaultPath: adapter instanceof FileSystemAdapter ? adapter.getBasePath() : null,
      duplicateNameSeparator: this.pluginSettingsComponent.settings.duplicateNameSeparator,
      fileBaseName: params.fileBaseName,
      fileExtension: params.fileExtension,
      folderPath: params.folderPath,
      isWindows
    });
    if (result.isShortened && params.shouldNotify) {
      const fileName = makeFileName({ fileBaseName: result.fileBaseName, fileExtension: params.fileExtension });
      console.warn(`Attachment file name "${makeFileName({ fileBaseName: params.fileBaseName, fileExtension: params.fileExtension })}" is too long for the file system, shortened to "${fileName}".`);
      this.pluginNoticeComponent.showNotice(t(($) => $.notice.attachmentFileNameShortened, { fileName }));
    }
    return result.fileBaseName;
  }

  private async getAttachmentFolderPath(substitutions: Substitutions): Promise<string> {
    /*
     * Collecting has its own destination when the user gave it one (issue #78): a working vault keeps new
     * attachments in a shared folder, while a note promoted to a portable export wants them gathered beside
     * it. An empty template means "wherever new attachments go", exactly as it does for the collected FILE
     * NAME in `getGeneratedAttachmentFileBaseName`, so a user who never opens this setting sees no change.
     */
    const settings = this.pluginSettingsComponent.settings;
    const collectedAttachmentFolderPath = settings.getOperationFolderPath(AttachmentOperation.Collect);
    if (isCollectActionContext(substitutions.actionContext) && collectedAttachmentFolderPath) {
      return await this.resolvePathTemplate({ isFileNamePart: false, substitutions, template: collectedAttachmentFolderPath });
    }

    // A new attachment's operation folder, in the same way: empty means wherever the default puts it.
    const newAttachmentFolderPath = substitutions.newAttachmentOperation === undefined ? '' : settings.getNewAttachmentFolderPath(substitutions.newAttachmentOperation);
    if (newAttachmentFolderPath) {
      return await this.resolvePathTemplate({ isFileNamePart: false, substitutions, template: newAttachmentFolderPath });
    }

    return settings.shouldFollowObsidianAttachmentLocation ? this.getObsidianAttachmentFolderPath(substitutions.noteFolderPath) : await this.resolvePathTemplate({ isFileNamePart: false, substitutions, template: settings.attachmentFolderPath });
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

  /**
   * Resolves Obsidian's own *Default location for new attachments* for a note, the way Obsidian does.
   *
   * Deliberately NOT routed through {@link resolvePathTemplate}: the value is a folder the user typed into
   * Obsidian, not a template, so a `{{` in it is a folder name rather than a token, and the special-character
   * cleaning must not rename a folder Obsidian itself would use as-is.
   *
   * The four shapes the setting stores are the vault root (`/`), a fixed folder (`assets`), the note's own
   * folder (`./`), and a subfolder of it (`./attachments`).
   *
   * @param noteFolderPath - The note's folder, `''` for the vault root.
   * @returns The attachment folder, `''` for the vault root.
   */
  private getObsidianAttachmentFolderPath(noteFolderPath: string): string {
    const configuredValue = this.app.vault.getConfig('attachmentFolderPath');
    const configuredPath = typeof configuredValue === 'string' ? configuredValue : '';
    let folderPath: string;
    if (configuredPath === '.' || configuredPath === './') {
      folderPath = noteFolderPath;
    } else if (configuredPath.startsWith('./')) {
      folderPath = join(noteFolderPath, configuredPath.slice('./'.length));
    } else {
      folderPath = configuredPath;
    }

    // Obsidian's `normalizePath` spells the vault root `/`; this plugin spells it `''`.
    return normalizePath(folderPath).replace(/^\/$/, '');
  }

  private isGeneratedAttachmentFileNameSkipped(context: AttachmentPathContext, shouldSkipGeneratedAttachmentFileName: boolean | undefined): boolean {
    /*
     * A note rename must not rename the attachment when the user turned that off. The setting reaches
     * obsidian-lib's `RenameDeleteHandlerComponent` only, so a plugin calling `getAttachmentFilePath` directly
     * would otherwise resolve a brand-new name here — and, with a `{{prompt}}` template, open a modal per
     * renamed note (issue #259 in `Advanced Note Composer`). Skipping the generated name leaves the file
     * named as it is and moves only its folder.
     */
    return shouldSkipGeneratedAttachmentFileName === true
      || (context === AttachmentPathContext.RenameNote && !this.handedOverSettingsComponent.settings.shouldRenameAttachmentFiles);
  }

  /**
   * Whether the attachment already sits at its proper path under a duplicate suffix, because a different
   * file holds the proper path itself.
   *
   * A move onto an occupied path lands on `<name><separator><n>`, which never equals the proper path. Without
   * this check, every later collect sees that mismatch and moves the file again, to the next free suffix.
   * With `Collect attachments automatically` on, each of those moves rewrites the note, which fires the next
   * collect, and the file is renamed without end. A parked file whose proper path has since come FREE is not
   * parked any more, and moving it there is a real improvement, so the proper path must still be occupied.
   *
   * @param attachmentFile - The attachment.
   * @param properPath - Where it belongs.
   * @returns `true` when there is nothing to move.
   */
  private isParkedBesideProperPath(attachmentFile: TFile, properPath: string): boolean {
    // The proper path always keeps the attachment's own extension, so only the folder and the base name can differ.
    if (dirname(attachmentFile.path) !== dirname(properPath)) {
      return false;
    }

    const properBaseName = basename(properPath, extname(properPath));
    const duplicateSuffixRegExp = new RegExp(
      String.raw`^${escapeRegExp(properBaseName)}${escapeRegExp(this.pluginSettingsComponent.settings.duplicateNameSeparator)}\d+$`,
      'u'
    );
    return duplicateSuffixRegExp.test(attachmentFile.basename) && getAbstractFileOrNull({
          app: this.app,
          isCaseInsensitive: true,
          pathOrFile: properPath
        }) !== null;
  }

  /**
   * Whether a resolver call is a query: one that skips both the duplicate check and the folder creation asks where an
   * attachment belongs, and nothing will be written at the path it returns.
   *
   * @param params - The resolver call.
   * @returns `true` for a query.
   */
  private isQuery(params: AttachmentPathManagerIsQueryParams): boolean {
    return params.shouldSkipDuplicateCheck === true && params.shouldSkipMissingAttachmentFolderCreation === true;
  }

  private async prepareInsertedLinkText(prepareParams: AttachmentPathManagerPrepareInsertedLinkTextParams): Promise<void> {
    const { attachmentFileBaseName, attachmentFileStats, attachmentPath, noteFilePath, originalAttachmentFileNameParams, params } = prepareParams;
    // Link generation is synchronous. Finish asynchronous tokens before handing the path to the importer.
    const template = this.pluginSettingsComponent.settings.insertedLinkText;
    const actionContext = attachmentPathContextToActionContext(params.context);
    if (!template || !noteFilePath || attachmentFileBaseName === DUMMY_PATH || isImageExtension(params.attachmentFileExtension) || actionContext !== ActionContext.Unknown) {
      return;
    }
    const text = await new Substitutions({
      actionContext,
      app: this.app,
      // The name the attachment has when its link is written, as for an existing file; the arrival name stays
      // the original one, which `originalAttachmentFileNameParams` always carries for an import.
      attachmentFileName: basename(attachmentPath),
      attachmentFileStats,
      generatedAttachmentFileName: basename(attachmentPath),
      generatedAttachmentFilePath: attachmentPath,
      noteFilePath,
      ...originalAttachmentFileNameParams,
      pluginSettingsComponent: this.pluginSettingsComponent,
      readAttachmentFileContent: params.readAttachmentFileContent ?? undefined,
      tokenValidator: this.tokenValidator
    }).fillTemplate(template);
    this.insertedLinkTexts.set(attachmentPath, { expiresAt: Date.now() + INSERTED_LINK_TEXT_LIFETIME_IN_MILLISECONDS, notePath: noteFilePath, template, text });
    if (this.insertedLinkTexts.size > MAX_INSERTED_LINK_TEXTS) {
      this.insertedLinkTexts.delete(ensureNonNullable(this.insertedLinkTexts.keys().next().value));
    }
  }

  /**
   * Resolves every reference of a note, remembering the answer until {@link invalidateNoteReferenceResolutions}.
   *
   * A caller auditing a note asks the resolver once per reference, and each answer walks the whole note, so without
   * this a note with `k` attachment links costs `k²` resolutions, each a vault-wide name lookup. Only the resolution
   * is remembered: the filtering in {@link walkNoteLinks} reads settings, which change without either signal.
   *
   * The key is the note's path alone. `getCacheSafe` wraps the cache in a new object on every call, so the object
   * cannot be the key, and it brings a stale note up to date through Obsidian, whose `changed` event invalidates
   * this before the lookup.
   *
   * @param noteFilePath - The note.
   * @param cache - Its current cache.
   * @returns Its references in order, each with the file it resolves to.
   */
  private resolveNoteReferences(noteFilePath: string, cache: CachedMetadata): readonly ResolvedNoteReference[] {
    const remembered = this.noteReferenceResolutions.get(noteFilePath);
    if (remembered) {
      return remembered;
    }

    const references = getReferences({ cache }).map((reference) => ({
      linkFile: extractReferenceFile({
        app: this.app,
        reference,
        sourcePathOrFile: noteFilePath
      }),
      reference
    }));
    this.noteReferenceResolutions.set(noteFilePath, references);
    if (this.noteReferenceResolutions.size > MAX_NOTE_REFERENCE_RESOLUTIONS) {
      this.noteReferenceResolutions.delete(ensureNonNullable(this.noteReferenceResolutions.keys().next().value));
    }
    return references;
  }

  /**
   * What a template reads as the original name of the attachment `getAvailablePathForAttachments` is asked about.
   *
   * A note rename or delete asks about an attachment that already exists, so its original name is the one on record.
   * Every other context places a new attachment, which arrives with the name it is asked about, unless the caller
   * already renamed it — the saver, or the share sheet, whose import renames each file before it gets here.
   *
   * @param resolveParams - The request, and the base name with any share-import prefix removed.
   * @returns The existing attachment, if any, and what to hand {@link Substitutions}.
   */
  private resolveOriginalAttachmentFileName(resolveParams: AttachmentPathManagerResolveOriginalAttachmentFileNameParams): ResolvedOriginalAttachmentFileName {
    const { params } = resolveParams;
    const existingAttachmentFile = params.context === AttachmentPathContext.RenameNote || params.context === AttachmentPathContext.DeleteNote
      ? getFileOrNull({ app: this.app, pathOrFile: params.oldAttachmentPathOrFile })
      : null;
    const incomingAttachmentFileName = makeFileName({
      fileBaseName: resolveParams.attachmentFileBaseName,
      fileExtension: params.attachmentFileExtension
    });
    const arrivalFileName = resolveParams.isGeneratedByShareReceiver
      ? getShareImportOriginalFileName(incomingAttachmentFileName) ?? incomingAttachmentFileName
      : params.originalAttachmentFileName ?? incomingAttachmentFileName;

    return {
      arrivalFileName,
      existingAttachmentFile,
      originalAttachmentFileNameParams: existingAttachmentFile
        ? this.getOriginalAttachmentFileNameParams(existingAttachmentFile, attachmentPathContextToActionContext(params.context))
        : { originalAttachmentFileName: arrivalFileName }
    };
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
      if (substitutions.actionContext === ActionContext.PreviewTemplates) {
        // The settings preview shows the error itself, on every keystroke, so it must not raise a notice too.
        throw error;
      }
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
   * Both `{{cursorLine}}` and `{{sequenceNumber}}` are derived from the same `getCacheSafe`/`getReferences`
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
    for (const { linkFile, reference: link } of this.resolveNoteReferences(noteFilePath, cache)) {
      // Cursor line: the first reference-cache link resolving to the target attachment. Checked before the
      // note-link filter below, matching the former getCursorLine which never applied that filter.
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
