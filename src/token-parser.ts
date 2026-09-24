import { parse } from 'json5';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import { parseObjectExpressionEndExclusive } from './parse-object-expression-end-exclusive.ts';

/**
 * The two token syntaxes the parser knows.
 *
 * `Templates` is the only one a template is evaluated in: `{{token}}`, `{{token:{...}}}` and the scalar shorthand
 * `{{token:text}}`, the same `{{...}}` language Obsidian core's Templates plugin teaches. `Legacy` is the retired
 * `${token}` / `${token:{...}}` syntax every release before 14.0.0 used; it is scanned only to migrate a stored
 * template and to name a leftover one in {@link LegacyTokenSyntaxError}.
 */
export enum TokenSyntax {
  Legacy = 'Legacy',
  Templates = 'Templates'
}

interface ScannedToken {
  end: number;
  formatText: null | string;
  /**
   * Whether {@link formatText} is the scalar shorthand (`{{date:YYYY-MM-DD}}`) rather than a JSON5 object.
   */
  isScalarFormat: boolean;
  raw: string;
  start: number;
  token: string;
}

interface SyntaxDefinition {
  readonly close: string;
  readonly headRegExp: RegExp;
  readonly isScalarFormatAllowed: boolean;
  readonly startRegExpSource: string;
}

const SYNTAX_DEFINITIONS: Record<TokenSyntax, SyntaxDefinition> = {
  [TokenSyntax.Legacy]: {
    close: '}',
    headRegExp: /\$\{\s*(?<Token>[a-zA-Z0-9_]+)\s*(?<Colon>:\s*)?/y,
    isScalarFormatAllowed: false,
    startRegExpSource: String.raw`\$\{`
  },
  [TokenSyntax.Templates]: {
    close: '}}',
    headRegExp: /\{\{\s*(?<Token>[a-zA-Z0-9_]+)\s*(?<Colon>:\s*)?/y,
    isScalarFormatAllowed: true,
    // A `{{` directly followed by another `{` is not a token start: in `{{{a}}}` the token is the inner `{{a}}`.
    startRegExpSource: String.raw`\{\{(?!\{)`
  }
};

// Loose on purpose: it names a leftover `${token...` even when the rest of it would not parse as a legacy token.
const LEGACY_TOKEN_HEAD_REGEXP = /\$\{\s*(?<Token>[a-zA-Z0-9_]+)\s*[:}]/;

interface CloseTokenParams {
  readonly formatText: null | string;
  readonly head: ParseHeadAtResult;
  readonly indexBeforeClose: number;
  readonly isScalarFormat: boolean;
  readonly params: ParseTokenAtParams;
}

interface MissingCloseErrorParams {
  readonly syntaxDefinition: SyntaxDefinition;
  readonly tokenName: string;
}

interface ParseFormatObjectParams {
  readonly formatText: string;
  readonly tokenName: string;
}

interface ParseHeadAtParams {
  readonly start: number;
  readonly string: string;
  readonly syntaxDefinition: SyntaxDefinition;
  readonly throwOnError: boolean;
}

interface ParseHeadAtResult {
  readonly hasColon: boolean;
  readonly indexAfterHead: number;
  readonly tokenName: string;
}

interface ParseScalarFormatTokenAtParams {
  readonly formatStart: number;
  readonly head: ParseHeadAtResult;
  readonly params: ParseTokenAtParams;
}

interface ParseTokenAtParams {
  readonly start: number;
  readonly string: string;
  readonly syntaxDefinition: SyntaxDefinition;
  readonly throwOnError: boolean;
}

interface ParseTokenFormatParams {
  readonly formatText: null | string;
  readonly isScalarFormat: boolean;
  readonly token: string;
}

interface ScanTokensOptions {
  readonly syntax?: TokenSyntax;
  readonly throwOnError?: boolean;
}

interface SkipWhitespaceParams {
  readonly start: number;
  readonly string: string;
}

/**
 * Thrown when a template still holds a token in the retired `${...}` syntax.
 *
 * An unparsed `${token}` is not an error to the scanner, it is literal text, so without this a template the settings
 * migration could not reach (a custom token's own `ctx.fillTemplate` call, say) would silently produce a wrong file
 * name. The message names the token and the `{{...}}` form replacing it.
 */
export class LegacyTokenSyntaxError extends Error {
  public constructor(public readonly legacyToken: string, public readonly replacement: string) {
    super(`The token '${legacyToken}' uses the '\${...}' syntax, which is no longer supported. Write it as '${replacement}' instead.`);
    this.name = 'LegacyTokenSyntaxError';
  }
}

/**
 * Finds the first token written in the retired `${...}` syntax.
 *
 * @param $string - The template to search.
 * @returns The error describing it, or `null` when there is none.
 */
export function findLegacyToken($string: string): LegacyTokenSyntaxError | null {
  const match = LEGACY_TOKEN_HEAD_REGEXP.exec($string);
  if (!match) {
    return null;
  }

  const legacyToken = scanTokens($string.slice(match.index), { syntax: TokenSyntax.Legacy, throwOnError: false })[0];
  if (legacyToken?.start === 0) {
    return new LegacyTokenSyntaxError(legacyToken.raw, migrateLegacyTokenSyntax(legacyToken.raw));
  }

  // The `Token` named group is guaranteed to be present because the regexp requires it.
  const tokenName = ensureNonNullable(match.groups?.['Token']);
  return new LegacyTokenSyntaxError(`\${${tokenName}`, `{{${tokenName}}}`);
}

/**
 * Rewrites every `${token}` / `${token:{...}}` into `{{token}}` / `{{token:{...}}}`.
 *
 * Driven by {@link scanTokens} under the legacy grammar rather than by a separate regexp, so the migration and the
 * parser can never disagree about what counted as a token. A format object is migrated recursively, which carries a
 * template nested in one (`${prompt:{defaultValueTemplate:'${originalAttachmentFileName}'}}`) over too. Text that
 * never parsed as a token is left exactly as it was.
 *
 * @param $string - The template in the legacy syntax.
 * @returns The template in the `{{...}}` syntax.
 */
export function migrateLegacyTokenSyntax($string: string): string {
  const tokens = scanTokens($string, { syntax: TokenSyntax.Legacy, throwOnError: false });
  let out = '';
  let lastOffset = 0;
  for (const token of tokens) {
    out += $string.slice(lastOffset, token.start);
    out += token.formatText === null ? `{{${token.token}}}` : `{{${token.token}:${migrateLegacyTokenSyntax(token.formatText)}}}`;
    lastOffset = token.end;
  }
  out += $string.slice(lastOffset);
  return out;
}

/**
 * Turns a scanned token's format text into the value its format schema receives.
 *
 * @param params - The scanned token.
 * @returns `null` for no format, the text itself for the scalar shorthand, and the parsed object otherwise.
 */
export function parseTokenFormat(params: ParseTokenFormatParams): null | Record<string, unknown> | string {
  if (params.formatText === null) {
    return null;
  }

  return params.isScalarFormat
    ? params.formatText
    : parseFormatObject({
      formatText: params.formatText,
      tokenName: params.token
    });
}

export function scanTokens($string: string, options?: ScanTokensOptions): ScannedToken[] {
  const isThrowOnError = options?.throwOnError ?? true;
  const syntax = options?.syntax ?? TokenSyntax.Templates;
  const syntaxDefinition = SYNTAX_DEFINITIONS[syntax];

  if (isThrowOnError && syntax === TokenSyntax.Templates) {
    const legacyTokenError = findLegacyToken($string);
    if (legacyTokenError) {
      throw legacyTokenError;
    }
  }

  const tokens: ScannedToken[] = [];
  const startRegExp = new RegExp(syntaxDefinition.startRegExpSource, 'g');

  let match: null | RegExpExecArray;
  while ((match = startRegExp.exec($string)) !== null) {
    const token = parseTokenAt({
      start: match.index,
      string: $string,
      syntaxDefinition,
      throwOnError: isThrowOnError
    });
    if (!token) {
      continue;
    }

    tokens.push(token);
    // A token is never scanned twice: anything inside its format (a nested template, say) belongs to it.
    startRegExp.lastIndex = token.end;
  }

  return tokens;
}

function closeToken(closeParams: CloseTokenParams): null | ScannedToken {
  const { head, params } = closeParams;
  const { close } = params.syntaxDefinition;
  const closeIndex = skipWhitespace({
    start: closeParams.indexBeforeClose,
    string: params.string
  });
  if (!params.string.startsWith(close, closeIndex)) {
    if (params.throwOnError) {
      throw missingCloseError({ syntaxDefinition: params.syntaxDefinition, tokenName: head.tokenName });
    }
    return null;
  }

  const end = closeIndex + close.length;
  return {
    end,
    formatText: closeParams.formatText,
    isScalarFormat: closeParams.isScalarFormat,
    raw: params.string.slice(params.start, end),
    start: params.start,
    token: head.tokenName
  };
}

function missingCloseError(params: MissingCloseErrorParams): Error {
  return new Error(`Token '${params.tokenName}' is missing closing '${params.syntaxDefinition.close}'`);
}

function parseFormatObject(params: ParseFormatObjectParams): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = parse(params.formatText);
  } catch (error) {
    throw new Error('Invalid JSON5', { cause: error });
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Format for token '${params.tokenName}' must be a JSON5 object`);
  }
  return parsed as Record<string, unknown>;
}

function parseHeadAt(params: ParseHeadAtParams): null | ParseHeadAtResult {
  const headRegExp = params.syntaxDefinition.headRegExp;
  headRegExp.lastIndex = params.start;
  const head = headRegExp.exec(params.string);
  if (!head) {
    if (params.throwOnError) {
      throw new Error('Invalid token start');
    }
    return null;
  }

  // `groups` is always present because the regexp declares named groups.
  const groups = ensureNonNullable(head.groups);
  // The `Token` named group is guaranteed to be present and non-empty because the regexp requires `[a-zA-Z0-9_]+`.
  const tokenName = ensureNonNullable(groups['Token']).trim();

  return {
    hasColon: Boolean(groups['Colon']),
    indexAfterHead: headRegExp.lastIndex,
    tokenName
  };
}

function parseScalarFormatTokenAt(scalarParams: ParseScalarFormatTokenAtParams): null | ScannedToken {
  const { formatStart, head, params } = scalarParams;
  const closeIndex = params.string.indexOf(params.syntaxDefinition.close, formatStart);
  if (closeIndex === -1) {
    if (params.throwOnError) {
      throw missingCloseError({ syntaxDefinition: params.syntaxDefinition, tokenName: head.tokenName });
    }
    return null;
  }

  const formatText = params.string.slice(formatStart, closeIndex).trimEnd();
  let errorMessage = '';
  if (formatText === '') {
    errorMessage = `Token '${head.tokenName}' has an empty format`;
  } else if (/[{}]/.test(formatText)) {
    errorMessage = `Token '${head.tokenName}' scalar format must not contain '{' or '}'`;
  }

  if (errorMessage) {
    if (params.throwOnError) {
      throw new Error(errorMessage);
    }
    return null;
  }

  return closeToken({
    formatText,
    head,
    indexBeforeClose: closeIndex,
    isScalarFormat: true,
    params
  });
}

function parseTokenAt(params: ParseTokenAtParams): null | ScannedToken {
  const { syntaxDefinition } = params;
  const head = parseHeadAt(params);
  if (!head) {
    return null;
  }

  // No format -> must close right away
  if (!head.hasColon) {
    return closeToken({
      formatText: null,
      head,
      indexBeforeClose: head.indexAfterHead,
      isScalarFormat: false,
      params
    });
  }

  const formatStart = head.indexAfterHead;
  if (params.string[formatStart] !== '{') {
    if (syntaxDefinition.isScalarFormatAllowed) {
      return parseScalarFormatTokenAt({ formatStart, head, params });
    }
    if (params.throwOnError) {
      throw new Error(`Token '${head.tokenName}' format must be a JSON5 object starting with '{'`);
    }
    return null;
  }

  // Format part: a JSON5 object `{...}`, whose extent acorn finds, so a `}}}` run needs no guessing.
  const objectEndExclusive = parseObjectExpressionEndExclusive({
    objectStart: formatStart,
    string: params.string,
    throwOnError: params.throwOnError,
    tokenName: head.tokenName
  });
  return objectEndExclusive === null
    ? null
    : closeToken({
      formatText: params.string.slice(formatStart, objectEndExclusive),
      head,
      indexBeforeClose: objectEndExclusive,
      isScalarFormat: false,
      params
    });
}

function skipWhitespace(params: SkipWhitespaceParams): number {
  let index = params.start;
  while (index < params.string.length && /\s/.test(ensureNonNullable(params.string[index]))) {
    index++;
  }
  return index;
}
