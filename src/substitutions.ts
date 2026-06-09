import type {
  App,
  FileStats
} from 'obsidian';
import type { Promisable } from 'type-fest';

// eslint-disable-next-line import-x/no-namespace -- Need to pass entire obsidian module.
import * as obsidian from 'obsidian';
import { printError } from 'obsidian-dev-utils/error';
import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import { getOsUnsafePathCharsRegExp } from 'obsidian-dev-utils/obsidian/validation';
import {
  basename,
  dirname,
  extname
} from 'obsidian-dev-utils/path';
import {
  trimEnd,
  trimStart
} from 'obsidian-dev-utils/string';

import type { Plugin } from './plugin.ts';
import type { TokenEvaluatorContext } from './token-evaluator-context.ts';
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

export type TokenEvaluator = (ctx: TokenEvaluatorContext) => Promisable<string>;

interface Token {
  end: number;
  formatText: null | string;
  raw: string;
  start: number;
  token: string;
}

const MORE_THAN_TWO_DOTS_REG_EXP = /^\.{3,}$/;
const TRAILING_DOTS_REG_EXP = /\.+$/;

export enum TokenValidationMode {
  Error = 'Error',
  Skip = 'Skip',
  Validate = 'Validate'
}

export interface ValidatePathParams {
  readonly areTokensAllowed: boolean;
  readonly path: string;
  readonly plugin: Plugin;
}

type RegisterCustomTokenFn = (token: string, evaluator: TokenEvaluator) => void;

type RegisterCustomTokensWrapperFn = (registerCustomToken: RegisterCustomTokenFn) => void;

interface SubstitutionsConstructorParams {
  readonly actionContext: ActionContext;
  readonly attachmentFileContent?: ArrayBuffer | undefined;
  readonly attachmentFileStat?: FileStats | undefined;
  readonly cursorLine?: number | undefined;
  readonly generatedAttachmentFileName?: string;
  readonly generatedAttachmentFilePath?: string;
  readonly noteFilePath: string;
  readonly oldNoteFilePath?: string | undefined;
  readonly originalAttachmentFileName?: string;
  readonly plugin: Plugin;
  readonly sequenceNumber?: number | undefined;
}

interface ValidateFileNameOptions {
  readonly areSingleDotsAllowed: boolean;
  readonly fileName: string;
  readonly isEmptyAllowed: boolean;
  readonly plugin: Plugin;
  readonly tokenValidationMode: TokenValidationMode;
}

export class Substitutions {
  private static readonly registeredTokens = new Map<string, TokenBase<unknown>>();
  static {
    this.registerCustomTokens('');
  }

  public readonly actionContext: ActionContext;
  public readonly noteFolderPath: string;

  public readonly plugin: Plugin;
  private readonly app: App;
  private readonly attachmentFileContent: ArrayBuffer | undefined;
  private readonly attachmentFileStat: FileStats | undefined;
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
  private readonly sequenceNumber: number | undefined;

  public constructor(params: SubstitutionsConstructorParams) {
    this.plugin = params.plugin;
    this.app = params.plugin.app;
    this.actionContext = params.actionContext;

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
    this.attachmentFileStat = params.attachmentFileStat;

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

    const customTokens = parseCustomTokens(customTokensStr) ?? [];
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

    const tokens = scanTokens(template);

    let out = '';
    let lastOffset = 0;

    for (const t of tokens) {
      abortSignal.throwIfAborted();

      out += template.slice(lastOffset, t.start);
      lastOffset = t.end;

      const token = Substitutions.registeredTokens.get(t.token.toLowerCase());
      if (!token) {
        throw new Error(`Unknown token '${t.token}'.`);
      }

      const format = t.formatText === null ? null : parseFormatObject(t.formatText, t.token);

      const ctx: TokenEvaluatorContext = {
        abortSignal,
        actionContext: this.actionContext,
        app: this.app,
        attachmentFileContent: this.attachmentFileContent,
        attachmentFileStat: this.attachmentFileStat,
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
        plugin: this.plugin,
        sequenceNumber: this.sequenceNumber ?? 0,
        token: t.token,
        tokenEndOffset: t.end,
        tokenStartOffset: t.start,
        tokenWithFormat: t.raw,
        validatePath
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

export function parseCustomTokens(customTokensStr: string): CustomToken[] | null {
  const customTokens: CustomToken[] = [];
  try {
    // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func -- Need to create function from string.
    const registerCustomTokensWrapperFn = new Function('registerCustomToken', customTokensStr) as RegisterCustomTokensWrapperFn;

    registerCustomTokensWrapperFn(registerCustomToken);
    return customTokens;
  } catch (e) {
    printError(new Error('Error registering custom tokens', { cause: e }));
    return null;
  }

  function registerCustomToken(token: string, evaluator: TokenEvaluator): void {
    customTokens.push(new CustomToken(token, evaluator));
  }
}

export async function validateFileName(options: ValidateFileNameOptions): Promise<string> {
  switch (options.tokenValidationMode) {
    case TokenValidationMode.Error: {
      if (scanTokens(options.fileName, { throwOnError: false }).length > 0) {
        return 'Tokens are not allowed in file name';
      }
      break;
    }
    case TokenValidationMode.Skip:
      break;
    case TokenValidationMode.Validate: {
      const validationMessage = await validateTokens(options.plugin, options.fileName);
      if (validationMessage) {
        return validationMessage;
      }
      break;
    }
    default:
      throw new Error(`Invalid token validation mode: ${options.tokenValidationMode as string}`);
  }

  let cleanFileName: string;
  try {
    cleanFileName = removeTokens(options.fileName);
  } catch {
    return `Invalid token syntax in file name "${options.fileName}"`;
  }

  if (cleanFileName === '.' || cleanFileName === '..') {
    return options.areSingleDotsAllowed ? '' : 'Single dots are not allowed in file name';
  }

  if (!cleanFileName) {
    return options.isEmptyAllowed ? '' : 'File name is empty';
  }

  if (getOsUnsafePathCharsRegExp().test(cleanFileName)) {
    return `File name "${options.fileName}" contains invalid symbols`;
  }

  if (MORE_THAN_TWO_DOTS_REG_EXP.test(cleanFileName)) {
    return `File name "${options.fileName}" contains more than two dots`;
  }

  if (TRAILING_DOTS_REG_EXP.test(cleanFileName)) {
    return `File name "${options.fileName}" contains trailing dots`;
  }

  return '';
}

export async function validatePath(params: ValidatePathParams): Promise<string> {
  if (params.areTokensAllowed) {
    const unknownToken = await validateTokens(params.plugin, params.path);
    if (unknownToken) {
      return `Unknown token: ${unknownToken}`;
    }
  } else if (scanTokens(params.path, { throwOnError: false }).length > 0) {
    return 'Tokens are not allowed in path';
  }

  let path = trimStart(params.path, '/');
  path = trimEnd(path, '/');

  if (path === '') {
    return '';
  }

  const pathParts = path.split('/');
  for (const part of pathParts) {
    const partValidationError = await validateFileName({
      areSingleDotsAllowed: true,
      fileName: part,
      isEmptyAllowed: true,
      plugin: params.plugin,
      tokenValidationMode: TokenValidationMode.Skip
    });

    if (partValidationError) {
      return partValidationError;
    }
  }

  return '';
}

function dotToEmpty(name: string): string {
  return name === '.' ? '' : name;
}

function extractTokens(str: string): Token[] {
  return scanTokens(str, { throwOnError: false });
}

function removeTokens(str: string): string {
  const tokens = scanTokens(str);
  let out = '';
  let lastOffset = 0;
  for (const t of tokens) {
    out += str.slice(lastOffset, t.start);
    out += `__${t.token}__`;
    lastOffset = t.end;
  }
  out += str.slice(lastOffset);
  return out;
}

async function validateTokens(plugin: Plugin, str: string): Promise<null | string> {
  const FAKE_SUBSTITUTION = new Substitutions({
    actionContext: ActionContext.ValidateTokens,
    noteFilePath: DUMMY_PATH,
    originalAttachmentFileName: DUMMY_PATH,
    plugin
  });

  const tokens = extractTokens(str);

  for (const t of tokens) {
    if (!Substitutions.isRegisteredToken(t.token)) {
      return `Unknown token '${t.token}'.`;
    }

    // Validate the format object is parseable JSON5 (if present).
    if (t.formatText !== null) {
      try {
        parseFormatObject(t.formatText, t.token);
      } catch (e) {
        return `Invalid format for token '${t.token}': ${(e as Error).message}`;
      }
    }

    // Validate token-specific schema by evaluating in a safe context.
    try {
      await FAKE_SUBSTITUTION.fillTemplate(t.raw);
    } catch (e) {
      return `Invalid token '${t.raw}': ${(e as Error).message}`;
    }
  }

  return null;
}
