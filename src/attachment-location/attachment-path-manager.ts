import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { PathOrFile } from '@mnaoumov/obsidian-lib/file-system';
import type {
  App,
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
import { appendCodeBlock } from '@mnaoumov/obsidian-lib/html-element';
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
import { normalizePath } from 'obsidian';

import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from '../original-attachment-names/original-attachment-names-component.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentFileNameParams } from '../tokens/substitutions.ts';

import { isImageExtension } from '../attachment-saving/image-mime-types.ts';
import { selfWriteRegistry } from '../externally-created-attachments/self-write-registry.ts';
import {
  formatString,
  stringFormatSchema
} from '../tokens/base/string-token-base.ts';
import { Substitutions } from '../tokens/substitutions.ts';
import {
  ActionContext,
  attachmentPathContextToActionContext,
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
import { findIdenticalAttachmentFile } from './identical-attachment.ts';
import {
  getShareImportOriginalFileName,
  IMPORT_FILES_PREFIX
} from './share-receiver-import-files-patch-component.ts';

const ORIGINAL_ATTACHMENT_FILE_NAME_TEMPLATE = '{{originalAttachmentFileName}}';
const ORIGINAL_ATTACHMENT_FILE_NAME_TOKEN = 'originalAttachmentFileName'.toLowerCase();
const ORIGINAL_ATTACHMENT_FILE_EXTENSION_TOKEN = 'originalAttachmentFileExtension'.toLowerCase();
const MAX_INSERTED_LINK_TEXTS = 100;
const INSERTED_LINK_TEXT_LIFETIME_IN_MILLISECONDS = 60_000;

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

interface AttachmentPathManagerGetAttachmentFolderFullPathForPathParams {
  readonly actionContext: ActionContext;
  readonly attachmentFileContent?: ArrayBuffer | undefined;
  readonly attachmentFileName: string;
  readonly attachmentFileStats?: FileStats | undefined;
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

interface AttachmentPathManagerPrepareInsertedLinkTextParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileStats: FileStats | undefined;
  readonly attachmentPath: string;
  readonly noteFilePath: string | undefined;
  readonly originalAttachmentFileNameParams: OriginalAttachmentFileNameParams;
  readonly params: AttachmentPathManagerGetAvailablePathForAttachmentsParams;
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
     * would otherwise be renamed (and, with `{{prompt}}`, prompted for) a second time.
     *
     * Claiming a path that never gets written costs nothing: the entry expires, and it is only ever
     * consumed by a creation at exactly that path — which would mean the writer used the name this
     * plugin gave it, and so needs no renaming anyway.
     *
     * Not when the name was the CALLER's, though. `VaultGetAvailablePathForAttachmentsPatchComponent` hands
     * out paths whose file name it passed through untouched, so it downgrades this claim to one that holds only
     * while core Obsidian is the writer (issue #65).
     */
    selfWriteRegistry.register(attachmentPath);

    this.expectArrivalOfNewAttachment(attachmentPath, resolvedOriginalAttachmentFileName);

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
    const generatedAttachmentFileNameBaseName = basename(generatedAttachmentFileNamePath, params.fileExtension ? `.${params.fileExtension}` : '');
    const attachmentPath = this.app.vault.getAvailablePath(join(directory, generatedAttachmentFileNameBaseName), params.fileExtension);
    this.originalAttachmentNamesComponent.expectArrival(attachmentPath, attachmentFileName);

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
       * it here renames files the user never asked to rename (and prompts, when it holds a `{{prompt}}`
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

  public getInsertedLinkText(params: AttachmentPathManagerGetInsertedLinkTextParams): string | undefined {
    const prepared = this.takeInsertedLinkText({ attachmentPath: params.attachmentFile.path, notePath: params.notePath });
    if (prepared !== undefined) {
      return prepared;
    }
    // Existing files have no asynchronous import in flight. The original-name tokens can read the durable
    // store synchronously, including after collect/rename; other templates require an import preparation.
    const template = this.pluginSettingsComponent.settings.insertedLinkText;
    const tokens = scanTokens(template).map((token) => ({ ...token, token: token.token.toLowerCase() }));
    if (tokens.some((token) => token.token !== ORIGINAL_ATTACHMENT_FILE_NAME_TOKEN && token.token !== ORIGINAL_ATTACHMENT_FILE_EXTENSION_TOKEN)) {
      return undefined;
    }
    const originalNameParams = this.getOriginalAttachmentFileNameParams(params.attachmentFile, ActionContext.Unknown);
    const originalName = originalNameParams.originalAttachmentFileName ?? params.attachmentFile.name;
    if (tokens.length > 0) {
      originalNameParams.onOriginalAttachmentFileNameUnknown?.();
    }
    const extension = extname(originalName);
    let text = '';
    let offset = 0;
    for (const token of tokens) {
      const value = token.token === ORIGINAL_ATTACHMENT_FILE_NAME_TOKEN ? basename(originalName, extension) : extension.slice(1);
      text += template.slice(offset, token.start) + formatString(value, stringFormatSchema.parse(parseTokenFormat(token) ?? {}));
      offset = token.end;
    }
    return text + template.slice(offset) || undefined;
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
    if (originalAttachmentFileName !== undefined) {
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
   * Builds a map from attachment file path to its 1-based sequence number within the note.
   *
   * The `Collect attachments` command must compute this **before** it moves any attachment: a move
   * rewrites the note's links, which would shift the numbering of the attachments processed later in
   * the same pass. Snapshotting the numbering up front keeps each attachment's `{{sequenceNumber}}`
   * stable regardless of move order.
   */
  public async getSequenceNumberMap(noteFilePath: string): Promise<Map<string, number>> {
    const { sequenceNumberByAttachmentPath } = await this.walkNoteLinks(noteFilePath, null);
    return sequenceNumberByAttachmentPath;
  }

  public takeInsertedLinkText(params: AttachmentPathManagerTakeInsertedLinkTextParams): string | undefined {
    const entry = this.insertedLinkTexts.get(params.attachmentPath);
    if (!entry || entry.expiresAt < Date.now() || entry.notePath !== params.notePath || entry.template !== this.pluginSettingsComponent.settings.insertedLinkText) {
      return undefined;
    }
    this.insertedLinkTexts.delete(params.attachmentPath);
    return entry.text || undefined;
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

  private async getAttachmentFolderPath(substitutions: Substitutions): Promise<string> {
    /*
     * Collecting has its own destination when the user gave it one (issue #78): a working vault keeps new
     * attachments in a shared folder, while a note promoted to a portable export wants them gathered beside
     * it. An empty template means "wherever new attachments go", exactly as it does for the collected FILE
     * NAME in `getGeneratedAttachmentFileBaseName`, so a user who never opens this setting sees no change.
     */
    const settings = this.pluginSettingsComponent.settings;
    if (substitutions.actionContext === ActionContext.CollectAttachments && settings.collectedAttachmentFolderPath) {
      return await this.resolvePathTemplate({ isFileNamePart: false, substitutions, template: settings.collectedAttachmentFolderPath });
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
      attachmentFileName: makeFileName({ fileBaseName: attachmentFileBaseName, fileExtension: params.attachmentFileExtension }),
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
    for (const link of getReferences({ cache })) {
      const linkFile = extractReferenceFile({
        app: this.app,
        reference: link,
        sourcePathOrFile: noteFilePath
      });

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
