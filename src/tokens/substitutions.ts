import type {
  App,
  FileStats
} from 'obsidian';

import {
  basename,
  dirname,
  extname
} from '@mnaoumov/typescript-lib/path';
// eslint-disable-next-line import-x/no-namespace -- Need to pass entire obsidian module.
import * as obsidian from 'obsidian';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { TokenBase } from './base/token-base.ts';
import type { TokenEvaluatorContext } from './token-evaluator-context.ts';
import type { TokenValidator } from './token-validator.ts';

import { AttachmentFileCreationDateToken } from './attachment/attachment-file-creation-date-token.ts';
import { AttachmentFileExtensionToken } from './attachment/attachment-file-extension-token.ts';
import { AttachmentFileHashToken } from './attachment/attachment-file-hash-token.ts';
import { AttachmentFileModificationDateToken } from './attachment/attachment-file-modification-date-token.ts';
import { AttachmentFileNameToken } from './attachment/attachment-file-name-token.ts';
import { AttachmentFileSizeToken } from './attachment/attachment-file-size-token.ts';
import { GeneratedAttachmentFileNameToken } from './attachment/generated-attachment-file-name-token.ts';
import { GeneratedAttachmentFilePathToken } from './attachment/generated-attachment-file-path-token.ts';
import { CustomToken } from './custom/custom-token.ts';
import { DateToken } from './generic/date-token.ts';
import { RandomToken } from './generic/random-token.ts';
import { SequenceNumberToken } from './generic/sequence-number-token.ts';
import { UuidToken } from './generic/uuid-token.ts';
import { FrontmatterToken } from './note/frontmatter-token.ts';
import { HeadingToken } from './note/heading-token.ts';
import { NoteFileCreationDateToken } from './note/note-file-creation-date-token.ts';
import { NoteFileModificationDateToken } from './note/note-file-modification-date-token.ts';
import { NoteFileNameToken } from './note/note-file-name-token.ts';
import { NoteFilePathToken } from './note/note-file-path-token.ts';
import { NoteFolderNameToken } from './note/note-folder-name-token.ts';
import { NoteFolderPathToken } from './note/note-folder-path-token.ts';
import { OriginalAttachmentFileCreationDateToken } from './original-attachment/original-attachment-file-creation-date-token.ts';
import { OriginalAttachmentFileExtensionToken } from './original-attachment/original-attachment-file-extension-token.ts';
import { OriginalAttachmentFileModificationDateToken } from './original-attachment/original-attachment-file-modification-date-token.ts';
import { OriginalAttachmentFileNameToken } from './original-attachment/original-attachment-file-name-token.ts';
import { PromptToken } from './prompt/prompt-token.ts';
import {
  ActionContext,
  TemplatePart
} from './token-evaluator-context.ts';
import {
  parseTokenFormat,
  scanTokens
} from './token-parser.ts';

/**
 * What a template reads as an attachment's original name: the name on record, or a report to make when it is not
 * known and the current name stands in.
 */
export type OriginalAttachmentFileNameParams = Pick<SubstitutionsConstructorParams, 'onOriginalAttachmentFileNameUnknown' | 'originalAttachmentFileName'>;

interface SubstitutionsConstructorParams {
  readonly actionContext: ActionContext;
  readonly app: App;
  readonly attachmentFileContent?: ArrayBuffer | undefined;

  /**
   * The attachment's name as it is right now, extension included. Defaults to {@link originalAttachmentFileName}.
   */
  readonly attachmentFileName?: string | undefined;
  readonly attachmentFileStats?: FileStats | undefined;
  readonly cursorLine?: number | undefined;
  readonly generatedAttachmentFileName?: string;
  readonly generatedAttachmentFilePath?: string;
  readonly noteFilePath: string;
  readonly oldNoteFilePath?: string | undefined;

  /**
   * Called the first time a template reads the original name while it is not known, which is when the current
   * name stands in for it. Leave it out where the current name IS the original, as it is for a file arriving now.
   */
  readonly onOriginalAttachmentFileNameUnknown?: (() => void) | undefined;

  /**
   * The name the attachment arrived with, extension included. Defaults to {@link attachmentFileName}.
   */
  readonly originalAttachmentFileName?: string | undefined;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly readAttachmentFileContent?: (() => Promise<ArrayBuffer>) | undefined;
  readonly sequenceNumber?: number | undefined;
  readonly tokenValidator: TokenValidator;
}

export class Substitutions {
  private static registeredCustomTokensString = '';
  private static readonly registeredTokens = new Map<string, TokenBase<unknown>>();
  static {
    this.registerCustomTokens('');
  }

  public readonly actionContext: ActionContext;

  public readonly noteFolderPath: string;
  private readonly app: App;
  private readonly attachmentFileContent: ArrayBuffer | undefined;
  private attachmentFileContentPromise: Promise<ArrayBuffer | undefined> | undefined;
  private readonly attachmentFileExtension: string;
  private readonly attachmentFileName: string;
  private readonly attachmentFileStats: FileStats | undefined;
  private readonly cursorLine: null | number;
  private readonly generatedAttachmentFileName: string;
  private readonly generatedAttachmentFilePath: string;
  private readonly noteFileName: string;
  private readonly noteFilePath: string;
  private readonly noteFolderName: string;
  private readonly oldNoteFileName: string;
  private readonly oldNoteFilePath: string;
  private readonly oldNoteFolderName: string;
  private readonly oldNoteFolderPath: string;
  private onOriginalAttachmentFileNameUnknown: (() => void) | undefined;
  private readonly originalAttachmentFileExtension: string;
  private readonly originalAttachmentFileName: string;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly readAttachmentFileContent: (() => Promise<ArrayBuffer>) | undefined;
  private readonly sequenceNumber: number | undefined;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: SubstitutionsConstructorParams) {
    this.app = params.app;
    this.actionContext = params.actionContext;
    this.pluginSettingsComponent = params.pluginSettingsComponent;

    this.noteFilePath = params.noteFilePath;
    this.noteFileName = basename(this.noteFilePath, extname(this.noteFilePath));
    this.noteFolderName = dotToEmpty(basename(dirname(this.noteFilePath)));
    this.noteFolderPath = dotToEmpty(dirname(this.noteFilePath));

    this.oldNoteFilePath = params.oldNoteFilePath ?? '';
    this.oldNoteFileName = basename(this.oldNoteFilePath, extname(this.oldNoteFilePath));
    this.oldNoteFolderName = dotToEmpty(basename(dirname(this.oldNoteFilePath)));
    this.oldNoteFolderPath = dotToEmpty(dirname(this.oldNoteFilePath));

    const attachmentFileName = params.attachmentFileName ?? params.originalAttachmentFileName ?? '';
    const attachmentFileExtension = extname(attachmentFileName);
    this.attachmentFileName = basename(attachmentFileName, attachmentFileExtension);
    this.attachmentFileExtension = attachmentFileExtension.slice(1);

    const originalAttachmentFileName = params.originalAttachmentFileName ?? attachmentFileName;
    const originalAttachmentFileExtension = extname(originalAttachmentFileName);
    this.originalAttachmentFileName = basename(originalAttachmentFileName, originalAttachmentFileExtension);
    this.originalAttachmentFileExtension = originalAttachmentFileExtension.slice(1);
    this.onOriginalAttachmentFileNameUnknown = params.originalAttachmentFileName === undefined ? params.onOriginalAttachmentFileNameUnknown : undefined;

    this.attachmentFileContent = params.attachmentFileContent;
    this.readAttachmentFileContent = params.readAttachmentFileContent;
    this.attachmentFileStats = params.attachmentFileStats;

    this.generatedAttachmentFileName = params.generatedAttachmentFileName ?? '';
    this.generatedAttachmentFilePath = params.generatedAttachmentFilePath ?? '';

    if (params.cursorLine === undefined) {
      this.cursorLine = null;

      if (this.app.workspace.activeEditor?.file?.path === this.noteFilePath) {
        const cursor = this.app.workspace.activeEditor.editor?.getCursor();
        if (cursor) {
          this.cursorLine = cursor.line;
        }
      }
    } else {
      this.cursorLine = params.cursorLine;
    }

    this.sequenceNumber = params.sequenceNumber;
    this.tokenValidator = params.tokenValidator;
  }

  /**
   * Registers the custom tokens unless that exact code is the one registered last.
   *
   * Registering runs the user's code, so a caller that re-asserts an unchanged value on every validation does not
   * re-run it. The comparison is against the last {@link registerCustomTokens} call from anywhere, so a direct
   * registration (the settings tab's own) is never mistaken for the older value.
   *
   * @param customTokensString - The custom tokens code.
   */
  public static ensureCustomTokensRegistered(customTokensString: string): void {
    if (customTokensString !== this.registeredCustomTokensString) {
      this.registerCustomTokens(customTokensString);
    }
  }

  public static isRegisteredToken(token: string): boolean {
    return this.registeredTokens.has(token.toLowerCase());
  }

  public static registerCustomTokens(customTokensString: string): void {
    this.registeredCustomTokensString = customTokensString;
    this.registeredTokens.clear();
    this.registerToken(new AttachmentFileCreationDateToken());
    this.registerToken(new AttachmentFileExtensionToken());
    this.registerToken(new AttachmentFileHashToken());
    this.registerToken(new AttachmentFileModificationDateToken());
    this.registerToken(new AttachmentFileNameToken());
    this.registerToken(new AttachmentFileSizeToken());
    this.registerToken(new DateToken());
    this.registerToken(new FrontmatterToken());
    this.registerToken(new GeneratedAttachmentFileNameToken());
    this.registerToken(new GeneratedAttachmentFilePathToken());
    this.registerToken(new HeadingToken());
    this.registerToken(new NoteFileCreationDateToken());
    this.registerToken(new NoteFileModificationDateToken());
    this.registerToken(new NoteFileNameToken());
    this.registerToken(new NoteFilePathToken());
    this.registerToken(new NoteFolderNameToken());
    this.registerToken(new NoteFolderPathToken());
    this.registerToken(new OriginalAttachmentFileCreationDateToken());
    this.registerToken(new OriginalAttachmentFileExtensionToken());
    this.registerToken(new OriginalAttachmentFileModificationDateToken());
    this.registerToken(new OriginalAttachmentFileNameToken());
    this.registerToken(new PromptToken());
    this.registerToken(new RandomToken());
    this.registerToken(new SequenceNumberToken());
    this.registerToken(new UuidToken());

    const customTokens = CustomToken.parse(customTokensString) ?? [];
    for (const customToken of customTokens) {
      this.registerToken(customToken);
    }
  }

  private static registerToken(token: TokenBase<unknown>): void {
    this.registeredTokens.set(token.name.toLowerCase(), token);
  }

  public async fillTemplate(template: string, templatePart: TemplatePart = TemplatePart.Other): Promise<string> {
    const abortController = new AbortController();
    const abortSignal = abortController.signal;

    const scannedTokens = scanTokens(template);

    let out = '';
    let lastOffset = 0;

    for (const scannedToken of scannedTokens) {
      abortSignal.throwIfAborted();

      out += template.slice(lastOffset, scannedToken.start);
      lastOffset = scannedToken.end;

      const token = Substitutions.registeredTokens.get(scannedToken.token.toLowerCase());
      if (!token) {
        throw new Error(`Unknown token '${scannedToken.token}'.`);
      }

      const format = parseTokenFormat(scannedToken);

      const context: TokenEvaluatorContext = {
        abortSignal,
        actionContext: this.actionContext,
        app: this.app,
        attachmentFileExtension: this.attachmentFileExtension,
        attachmentFileName: this.attachmentFileName,
        attachmentFileStats: this.attachmentFileStats,
        cursorLine: this.cursorLine,
        /*
         * Bound to the enclosing `templatePart` so a nested fill (a custom token calling
         * `ctx.fillTemplate`, or `{{prompt}}` resolving its `defaultValueTemplate`) inherits it. The
         * exposed signature stays one-argument, as the custom-token API documents it.
         */
        fillTemplate: (nestedTemplate: string) => this.fillTemplate(nestedTemplate, templatePart),
        format,
        fullTemplate: template,
        generatedAttachmentFileName: this.generatedAttachmentFileName,
        generatedAttachmentFilePath: this.generatedAttachmentFilePath,
        getAttachmentFileContent: () => this.getAttachmentFileContent(),
        noteFileName: this.noteFileName,
        noteFilePath: this.noteFilePath,
        noteFolderName: this.noteFolderName,
        noteFolderPath: this.noteFolderPath,
        obsidian,
        oldNoteFileName: this.oldNoteFileName,
        oldNoteFilePath: this.oldNoteFilePath,
        oldNoteFolderName: this.oldNoteFolderName,
        oldNoteFolderPath: this.oldNoteFolderPath,
        originalAttachmentFileExtension: this.originalAttachmentFileExtension,
        originalAttachmentFileName: this.originalAttachmentFileName,
        pluginSettingsComponent: this.pluginSettingsComponent,
        sequenceNumber: this.sequenceNumber ?? 0,
        templatePart,
        token: scannedToken.token,
        tokenEndOffset: scannedToken.end,
        tokenStartOffset: scannedToken.start,
        tokenValidator: this.tokenValidator,
        tokenWithFormat: scannedToken.raw
      };
      this.reportOriginalAttachmentFileNameUnknownOnRead(context);

      const evaluated = await token.evaluate(context);
      abortSignal.throwIfAborted();
      if (typeof evaluated !== 'string') {
        console.error('Token returned non-string value.', { context, result: evaluated });
        throw new Error('Token returned non-string value');
      }
      out += evaluated;
    }

    out += template.slice(lastOffset);
    return out;
  }

  private getAttachmentFileContent(): Promise<ArrayBuffer | undefined> {
    this.attachmentFileContentPromise ??= this.attachmentFileContent === undefined
      ? this.readAttachmentFileContent?.() ?? Promise.resolve(undefined)
      : Promise.resolve(this.attachmentFileContent);
    return this.attachmentFileContentPromise;
  }

  private reportOriginalAttachmentFileNameUnknown(): void {
    const onOriginalAttachmentFileNameUnknown = this.onOriginalAttachmentFileNameUnknown;
    this.onOriginalAttachmentFileNameUnknown = undefined;
    onOriginalAttachmentFileNameUnknown?.();
  }

  /**
   * Turns the original-name fields into getters, so the fallback is reported only when a template actually reads
   * the original name. Reporting it for every attachment a collect looks at would warn about templates that never
   * use the token.
   *
   * @param context - The context about to be handed to a token.
   */
  private reportOriginalAttachmentFileNameUnknownOnRead(context: TokenEvaluatorContext): void {
    if (!this.onOriginalAttachmentFileNameUnknown) {
      return;
    }

    Object.defineProperties(context, {
      originalAttachmentFileExtension: {
        enumerable: true,
        get: (): string => {
          this.reportOriginalAttachmentFileNameUnknown();
          return this.originalAttachmentFileExtension;
        }
      },
      originalAttachmentFileName: {
        enumerable: true,
        get: (): string => {
          this.reportOriginalAttachmentFileNameUnknown();
          return this.originalAttachmentFileName;
        }
      }
    });
  }
}

function dotToEmpty(name: string): string {
  return name === '.' ? '' : name;
}
