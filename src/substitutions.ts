import type {
  App,
  FileStats
} from 'obsidian';

// eslint-disable-next-line import-x/no-namespace -- Need to pass entire obsidian module.
import * as obsidian from 'obsidian';
import {
  basename,
  dirname,
  extname
} from 'obsidian-dev-utils/path';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { TokenEvaluatorContext } from './token-evaluator-context.ts';
import type { TokenValidator } from './token-validator.ts';
import type { TokenBase } from './tokens/token-base.ts';

import { ActionContext } from './token-evaluator-context.ts';
import {
  parseFormatObject,
  scanTokens
} from './token-parser.ts';
import { AttachmentFileSizeToken } from './tokens/attachment-file-size-token.ts';
import { CustomToken } from './tokens/custom-token.ts';
import { DateToken } from './tokens/date-token.ts';
import { FrontmatterToken } from './tokens/frontmatter-token.ts';
import { GeneratedAttachmentFileNameToken } from './tokens/generated-attachment-file-name-token.ts';
import { GeneratedAttachmentFilePathToken } from './tokens/generated-attachment-file-path-token.ts';
import { HeadingToken } from './tokens/heading-token.ts';
import { NoteFileCreationDateToken } from './tokens/note-file-creation-date-token.ts';
import { NoteFileModificationDateToken } from './tokens/note-file-modification-date-token.ts';
import { NoteFileNameToken } from './tokens/note-file-name-token.ts';
import { NoteFilePathToken } from './tokens/note-file-path-token.ts';
import { NoteFolderNameToken } from './tokens/note-folder-name-token.ts';
import { NoteFolderPathToken } from './tokens/note-folder-path-token.ts';
import { OriginalAttachmentFileCreationDateToken } from './tokens/original-attachment-file-creation-date-token.ts';
import { OriginalAttachmentFileExtensionToken } from './tokens/original-attachment-file-extension-token.ts';
import { OriginalAttachmentFileModificationDateToken } from './tokens/original-attachment-file-modification-date-token.ts';
import { OriginalAttachmentFileNameToken } from './tokens/original-attachment-file-name-token.ts';
import { PromptToken } from './tokens/prompt-token.ts';
import { RandomToken } from './tokens/random-token.ts';
import { SequenceNumberToken } from './tokens/sequence-number-token.ts';
import { UuidToken } from './tokens/uuid-token.ts';

interface SubstitutionsConstructorParams {
  readonly actionContext: ActionContext;
  readonly app: App;
  readonly attachmentFileContent?: ArrayBuffer | undefined;
  readonly attachmentFileStats?: FileStats | undefined;
  readonly cursorLine?: number | undefined;
  readonly generatedAttachmentFileName?: string;
  readonly generatedAttachmentFilePath?: string;
  readonly noteFilePath: string;
  readonly oldNoteFilePath?: string | undefined;
  readonly originalAttachmentFileName?: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly sequenceNumber?: number | undefined;
  readonly tokenValidator: TokenValidator;
}

export class Substitutions {
  private static readonly registeredTokens = new Map<string, TokenBase<unknown>>();
  static {
    this.registerCustomTokens('');
  }

  public readonly actionContext: ActionContext;

  public readonly noteFolderPath: string;
  private readonly app: App;
  private readonly attachmentFileContent: ArrayBuffer | undefined;
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
  private readonly originalAttachmentFileExtension: string;
  private readonly originalAttachmentFileName: string;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
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

    const originalAttachmentFileName = params.originalAttachmentFileName ?? '';
    const originalAttachmentFileExtension = extname(originalAttachmentFileName);
    this.originalAttachmentFileName = basename(originalAttachmentFileName, originalAttachmentFileExtension);
    this.originalAttachmentFileExtension = originalAttachmentFileExtension.slice(1);

    this.attachmentFileContent = params.attachmentFileContent;
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

  public static isRegisteredToken(token: string): boolean {
    return Substitutions.registeredTokens.has(token.toLowerCase());
  }

  public static registerCustomTokens(customTokensStr: string): void {
    this.registeredTokens.clear();
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

    const customTokens = CustomToken.parse(customTokensStr) ?? [];
    for (const customToken of customTokens) {
      this.registerToken(customToken);
    }
  }

  private static registerToken(token: TokenBase<unknown>): void {
    this.registeredTokens.set(token.name.toLowerCase(), token);
  }

  public async fillTemplate(template: string): Promise<string> {
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

      const format = scannedToken.formatText === null
        ? null
        : parseFormatObject({
          formatText: scannedToken.formatText,
          tokenName: scannedToken.token
        });

      const ctx: TokenEvaluatorContext = {
        abortSignal,
        actionContext: this.actionContext,
        app: this.app,
        attachmentFileContent: this.attachmentFileContent,
        attachmentFileStats: this.attachmentFileStats,
        cursorLine: this.cursorLine,
        fillTemplate: this.fillTemplate.bind(this),
        format,
        fullTemplate: template,
        generatedAttachmentFileName: this.generatedAttachmentFileName,
        generatedAttachmentFilePath: this.generatedAttachmentFilePath,
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
        token: scannedToken.token,
        tokenEndOffset: scannedToken.end,
        tokenStartOffset: scannedToken.start,
        tokenValidator: this.tokenValidator,
        tokenWithFormat: scannedToken.raw
      };

      const evaluated = await token.evaluate(ctx);
      abortSignal.throwIfAborted();
      if (typeof evaluated !== 'string') {
        console.error('Token returned non-string value.', { ctx, result: evaluated });
        throw new Error('Token returned non-string value');
      }
      out += evaluated;
    }

    out += template.slice(lastOffset);
    return out;
  }
}

function dotToEmpty(name: string): string {
  return name === '.' ? '' : name;
}
