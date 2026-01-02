import type {
  App,
  FileStats
} from 'obsidian';
import type { Promisable } from 'type-fest';

// eslint-disable-next-line import-x/no-namespace -- Need to pass entire obsidian module.
import * as obsidian from 'obsidian';
import { printError } from 'obsidian-dev-utils/Error';
import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/AttachmentPath';
import { getOsUnsafePathCharsRegExp } from 'obsidian-dev-utils/obsidian/Validation';
import {
  basename,
  dirname,
  extname
} from 'obsidian-dev-utils/Path';
import {
  replaceAll,
  replaceAllAsync,
  trimEnd,
  trimStart
} from 'obsidian-dev-utils/String';

import type { Plugin } from './Plugin.ts';
import type { TokenEvaluatorContext } from './TokenEvaluatorContext.ts';
import type { TokenBase } from './Tokens/TokenBase.ts';

import { ActionContext } from './TokenEvaluatorContext.ts';
import { AttachmentFileSizeToken } from './Tokens/AttachmentFileSizeToken.ts';
import { CustomToken } from './Tokens/CustomToken.ts';
import { DateToken } from './Tokens/DateToken.ts';
import { FrontmatterToken } from './Tokens/FrontmatterToken.ts';
import { GeneratedAttachmentFileNameToken } from './Tokens/GeneratedAttachmentFileNameToken.ts';
import { GeneratedAttachmentFilePathToken } from './Tokens/GeneratedAttachmentFilePathToken.ts';
import { HeadingToken } from './Tokens/HeadingToken.ts';
import { NoteFileCreationDateToken } from './Tokens/NoteFileCreationDateToken.ts';
import { NoteFileModificationDateToken } from './Tokens/NoteFileModificationDateToken.ts';
import { NoteFileNameToken } from './Tokens/NoteFileNameToken.ts';
import { NoteFilePathToken } from './Tokens/NoteFilePathToken.ts';
import { NoteFolderNameToken } from './Tokens/NoteFolderNameToken.ts';
import { NoteFolderPathToken } from './Tokens/NoteFolderPathToken.ts';
import { OriginalAttachmentFileCreationDateToken } from './Tokens/OriginalAttachmentFileCreationDateToken.ts';
import { OriginalAttachmentFileExtensionToken } from './Tokens/OriginalAttachmentFileExtensionToken.ts';
import { OriginalAttachmentFileModificationDateToken } from './Tokens/OriginalAttachmentFileModificationDateToken.ts';
import { OriginalAttachmentFileNameToken } from './Tokens/OriginalAttachmentFileNameToken.ts';
import { PromptToken } from './Tokens/PromptToken.ts';
import { RandomToken } from './Tokens/RandomToken.ts';
import { SequenceNumberToken } from './Tokens/SequenceNumberToken.ts';
import { UuidToken } from './Tokens/UuidToken.ts';

export type TokenEvaluator = (ctx: TokenEvaluatorContext) => Promisable<string>;

interface Token {
  format: string;
  token: string;
}

const MORE_THAN_TWO_DOTS_REG_EXP = /^\.{3,}$/;
const TRAILING_DOTS_REG_EXP = /\.+$/;
const SUBSTITUTION_TOKEN_REG_EXP = /\${(?<Token>.+?)(?::(?<Format>.*?))?}/g;

export enum TokenValidationMode {
  Error = 'Error',
  Skip = 'Skip',
  Validate = 'Validate'
}

export interface ValidatePathOptions {
  areTokensAllowed: boolean;
  path: string;
  plugin: Plugin;
}

type RegisterCustomTokenFn = (token: string, evaluator: TokenEvaluator) => void;

type RegisterCustomTokensWrapperFn = (registerCustomToken: RegisterCustomTokenFn) => void;

interface SubstitutionsOptions {
  actionContext: ActionContext;
  attachmentFileContent?: ArrayBuffer | undefined;
  attachmentFileStat?: FileStats | undefined;
  cursorLine?: number | undefined;
  generatedAttachmentFileName?: string;
  generatedAttachmentFilePath?: string;
  noteFilePath: string;
  oldNoteFilePath?: string | undefined;
  originalAttachmentFileName?: string;
  plugin: Plugin;
  sequenceNumber?: number | undefined;
}

interface ValidateFileNameOptions {
  areSingleDotsAllowed: boolean;
  fileName: string;
  isEmptyAllowed: boolean;
  plugin: Plugin;
  tokenValidationMode: TokenValidationMode;
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

  public constructor(options: SubstitutionsOptions) {
    this.plugin = options.plugin;
    this.app = options.plugin.app;
    this.actionContext = options.actionContext;

    this.noteFilePath = options.noteFilePath;
    this.noteFileName = basename(this.noteFilePath, extname(this.noteFilePath));
    this.noteFolderName = dotToEmpty(basename(dirname(this.noteFilePath)));
    this.noteFolderPath = dotToEmpty(dirname(this.noteFilePath));

    this.oldNoteFilePath = options.oldNoteFilePath ?? '';
    this.oldNoteFileName = basename(this.oldNoteFilePath, extname(this.oldNoteFilePath));
    this.oldNoteFolderName = dotToEmpty(basename(dirname(this.oldNoteFilePath)));
    this.oldNoteFolderPath = dotToEmpty(dirname(this.oldNoteFilePath));

    const originalAttachmentFileName = options.originalAttachmentFileName ?? '';
    const originalAttachmentFileExtension = extname(originalAttachmentFileName);
    this.originalAttachmentFileName = basename(originalAttachmentFileName, originalAttachmentFileExtension);
    this.originalAttachmentFileExtension = originalAttachmentFileExtension.slice(1);

    this.attachmentFileContent = options.attachmentFileContent;
    this.attachmentFileStat = options.attachmentFileStat;

    this.generatedAttachmentFileName = options.generatedAttachmentFileName ?? '';
    this.generatedAttachmentFilePath = options.generatedAttachmentFilePath ?? '';

    if (options.cursorLine === undefined) {
      this.cursorLine = null;

      if (this.app.workspace.activeEditor?.file?.path === this.noteFilePath) {
        const cursor = this.app.workspace.activeEditor.editor?.getCursor();
        if (cursor) {
          this.cursorLine = cursor.line;
        }
      }
    } else {
      this.cursorLine = options.cursorLine;
    }
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
    return await replaceAllAsync(template, SUBSTITUTION_TOKEN_REG_EXP, async (abortSignal, args, tokenName) => {
      abortSignal.throwIfAborted();

      const token = Substitutions.registeredTokens.get(tokenName.toLowerCase());
      if (!token) {
        throw new Error(`Unknown token '${tokenName}'.`);
      }

      const formatObj = {}; // TODO

      const ctx: TokenEvaluatorContext = {
        abortSignal,
        actionContext: this.actionContext,
        app: this.app,
        attachmentFileContent: this.attachmentFileContent,
        attachmentFileStat: this.attachmentFileStat,
        cursorLine: this.cursorLine,
        fillTemplate: this.fillTemplate.bind(this),
        format: formatObj,
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
        token: tokenName,
        tokenEndOffset: args.offset + args.substring.length,
        tokenStartOffset: args.offset,
        tokenWithFormat: args.substring,
        validatePath
      };

      try {
        const result = await token.evaluate(ctx);
        abortSignal.throwIfAborted();

        if (typeof result !== 'string') {
          console.error('Token returned non-string value.', {
            ctx,
            result
          });
          throw new Error('Token returned non-string value');
        }
        return result;
      } catch (e) {
        throw new Error(`Error formatting token \${${tokenName}}`, { cause: e });
      }
    });
  }
}

export function hasPromptToken(str: string): boolean {
  return extractTokens(str).some((token) => token.token === 'prompt');
}

export async function validateFileName(options: ValidateFileNameOptions): Promise<string> {
  switch (options.tokenValidationMode) {
    case TokenValidationMode.Error: {
      const match = options.fileName.match(SUBSTITUTION_TOKEN_REG_EXP);
      if (match) {
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

  const cleanFileName = removeTokens(options.fileName);

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

export async function validatePath(options: ValidatePathOptions): Promise<string> {
  if (options.areTokensAllowed) {
    const unknownToken = await validateTokens(options.plugin, options.path);
    if (unknownToken) {
      return `Unknown token: ${unknownToken}`;
    }
  } else {
    const match = options.path.match(SUBSTITUTION_TOKEN_REG_EXP);
    if (match) {
      return 'Tokens are not allowed in path';
    }
  }

  let path = trimStart(options.path, '/');
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
      plugin: options.plugin,
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
  const matches = str.matchAll(SUBSTITUTION_TOKEN_REG_EXP);
  return Array.from(matches).map((match) => ({
    format: match.groups?.['Format'] ?? '',
    token: match.groups?.['Token'] ?? ''
  }));
}

function removeTokens(str: string): string {
  return replaceAll(str, SUBSTITUTION_TOKEN_REG_EXP, (_, token, format) => `_${token}_${format}_`);
}

async function validateTokens(plugin: Plugin, str: string): Promise<null | string> {
  const FAKE_SUBSTITUTION = new Substitutions({
    actionContext: ActionContext.ValidateTokens,
    noteFilePath: DUMMY_PATH,
    originalAttachmentFileName: DUMMY_PATH,
    plugin
  });

  const tokens = extractTokens(str);
  for (const token of tokens) {
    if (!Substitutions.isRegisteredToken(token.token)) {
      return `Unknown token '${token.token}'.`;
    }
    const singleFormats = token.format.split(',');
    for (const singleFormat of singleFormats) {
      try {
        await FAKE_SUBSTITUTION.fillTemplate(`\${${token.token}:${singleFormat}}`);
      } catch {
        return `Token '${token.token}' is used with unknown format '${singleFormat}'.`;
      }
    }
  }
  return null;
}
