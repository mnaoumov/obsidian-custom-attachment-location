import type { App } from 'obsidian';

import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import { getOsUnsafePathCharsRegExp } from 'obsidian-dev-utils/obsidian/validation';
import {
  trimEnd,
  trimStart
} from 'obsidian-dev-utils/string';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { Substitutions } from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';
import {
  parseFormatObject,
  scanTokens
} from './token-parser.ts';

export enum TokenValidationMode {
  Error = 'Error',
  Skip = 'Skip',
  Validate = 'Validate'
}

interface Token {
  end: number;
  formatText: null | string;
  raw: string;
  start: number;
  token: string;
}

interface TokenValidatorConstructorParams {
  readonly app: App;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

interface TokenValidatorValidateFileNameParams {
  readonly areSingleDotsAllowed: boolean;
  readonly fileName: string;
  readonly isEmptyAllowed: boolean;
  readonly tokenValidationMode: TokenValidationMode;
}

interface TokenValidatorValidatePathParams {
  readonly areTokensAllowed: boolean;
  readonly path: string;
}

export class TokenValidator {
  private readonly app: App;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: TokenValidatorConstructorParams) {
    this.app = params.app;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public async validateFileName(params: TokenValidatorValidateFileNameParams): Promise<string> {
    switch (params.tokenValidationMode) {
      case TokenValidationMode.Error: {
        if (scanTokens(params.fileName, { throwOnError: false }).length > 0) {
          return 'Tokens are not allowed in file name';
        }
        break;
      }
      case TokenValidationMode.Skip:
        break;
      case TokenValidationMode.Validate: {
        const validationMessage = await this.validateTokens(params.fileName);
        if (validationMessage) {
          return validationMessage;
        }
        break;
      }
      default:
        throw new Error(`Invalid token validation mode: ${params.tokenValidationMode as string}`);
    }

    let cleanFileName: string;
    try {
      cleanFileName = removeTokens(params.fileName);
    } catch {
      return `Invalid token syntax in file name "${params.fileName}"`;
    }

    if (cleanFileName === '.' || cleanFileName === '..') {
      return params.areSingleDotsAllowed ? '' : 'Single dots are not allowed in file name';
    }

    if (!cleanFileName) {
      return params.isEmptyAllowed ? '' : 'File name is empty';
    }

    if (getOsUnsafePathCharsRegExp().test(cleanFileName)) {
      return `File name "${params.fileName}" contains invalid symbols`;
    }

    if (MORE_THAN_TWO_DOTS_REG_EXP.test(cleanFileName)) {
      return `File name "${params.fileName}" contains more than two dots`;
    }

    if (TRAILING_DOTS_REG_EXP.test(cleanFileName)) {
      return `File name "${params.fileName}" contains trailing dots`;
    }

    return '';
  }

  public async validatePath(params: TokenValidatorValidatePathParams): Promise<string> {
    if (params.areTokensAllowed) {
      const unknownToken = await this.validateTokens(params.path);
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
      const partValidationError = await this.validateFileName({
        areSingleDotsAllowed: true,
        fileName: part,
        isEmptyAllowed: true,
        tokenValidationMode: TokenValidationMode.Skip
      });

      if (partValidationError) {
        return partValidationError;
      }
    }

    return '';
  }

  private async validateTokens(str: string): Promise<null | string> {
    const FAKE_SUBSTITUTION = new Substitutions({
      actionContext: ActionContext.ValidateTokens,
      app: this.app,
      noteFilePath: DUMMY_PATH,
      originalAttachmentFileName: DUMMY_PATH,
      pluginSettingsComponent: this.pluginSettingsComponent,
      tokenValidator: this
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
}

function extractTokens(str: string): Token[] {
  return scanTokens(str, { throwOnError: false });
}

const MORE_THAN_TWO_DOTS_REG_EXP = /^\.{3,}$/;
const TRAILING_DOTS_REG_EXP = /\.+$/;

export function removeTokens(str: string): string {
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
