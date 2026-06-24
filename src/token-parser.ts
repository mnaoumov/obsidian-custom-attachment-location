import { parseExpressionAt } from 'acorn';
import { parse } from 'json5';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

interface ScannedToken {
  end: number;
  formatText: null | string;
  raw: string;
  start: number;
  token: string;
}

const TOKEN_HEAD_REGEXP = /\$\{\s*(?<Token>[a-zA-Z0-9_]+)\s*(?<Colon>:\s*)?/y;

interface ParseFormatObjectParams {
  readonly formatText: string;
  readonly tokenName: string;
}

interface ParseHeadAtParams {
  readonly start: number;
  readonly str: string;
  readonly throwOnError: boolean;
}

interface ParseHeadAtResult {
  readonly hasColon: boolean;
  readonly indexAfterHead: number;
  readonly tokenName: string;
}

interface ParseObjectExpressionEndExclusiveParams {
  readonly objectStart: number;
  readonly str: string;
  readonly throwOnError: boolean;
  readonly tokenName: string;
}

interface ParseTokenAtParams {
  readonly start: number;
  readonly str: string;
  readonly throwOnError: boolean;
}

interface ScanTokensOptions {
  readonly throwOnError?: boolean;
}

interface SkipWhitespaceParams {
  readonly start: number;
  readonly str: string;
}

export function parseFormatObject(params: ParseFormatObjectParams): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = parse(params.formatText);
  } catch (e) {
    throw new Error('Invalid JSON5', { cause: e });
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Format for token '${params.tokenName}' must be a JSON5 object`);
  }
  return parsed as Record<string, unknown>;
}

export function parseObjectExpressionEndExclusive(params: ParseObjectExpressionEndExclusiveParams): null | number {
  try {
    const node = parseExpressionAt(params.str, params.objectStart, { ecmaVersion: 'latest' });
    if (node.type !== 'ObjectExpression') {
      throw new Error(`Expected object literal, got ${node.type}`);
    }
    return node.end;
  } catch (e) {
    if (params.throwOnError) {
      throw new Error(`Invalid JSON5 object for token '${params.tokenName}'`, { cause: e });
    }
    return null;
  }
}

export function scanTokens(str: string, options?: ScanTokensOptions): ScannedToken[] {
  const throwOnError = options?.throwOnError ?? true;
  const tokens: ScannedToken[] = [];

  for (const match of str.matchAll(/\$\{/g)) {
    const start = match.index;
    const token = parseTokenAt({
      start,
      str,
      throwOnError
    });
    if (token) {
      tokens.push(token);
    }
  }

  return tokens;
}

function parseHeadAt(params: ParseHeadAtParams): null | ParseHeadAtResult {
  TOKEN_HEAD_REGEXP.lastIndex = params.start;
  const head = TOKEN_HEAD_REGEXP.exec(params.str);
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
    indexAfterHead: TOKEN_HEAD_REGEXP.lastIndex,
    tokenName
  };
}

function parseTokenAt(params: ParseTokenAtParams): null | ScannedToken {
  const head = parseHeadAt({
    start: params.start,
    str: params.str,
    throwOnError: params.throwOnError
  });
  if (!head) {
    return null;
  }

  // No format -> must close with `}`
  if (!head.hasColon) {
    const closeIdx = skipWhitespace({
      start: head.indexAfterHead,
      str: params.str
    });
    if (closeIdx >= params.str.length || params.str[closeIdx] !== '}') {
      if (params.throwOnError) {
        throw new Error(`Token '${head.tokenName}' is missing closing '}'`);
      }
      return null;
    }

    const end = closeIdx + 1;
    return {
      end,
      formatText: null,
      raw: params.str.slice(params.start, end),
      start: params.start,
      token: head.tokenName
    };
  }

  // Format part: must be JSON5 object `{...}`
  const objectStart = head.indexAfterHead;
  if (objectStart >= params.str.length || params.str[objectStart] !== '{') {
    if (params.throwOnError) {
      throw new Error(`Token '${head.tokenName}' format must be a JSON5 object starting with '{'`);
    }
    return null;
  }

  const objectEndExclusive = parseObjectExpressionEndExclusive({
    objectStart,
    str: params.str,
    throwOnError: params.throwOnError,
    tokenName: head.tokenName
  });
  if (objectEndExclusive === null) {
    return null;
  }

  const closeIdx = skipWhitespace({
    start: objectEndExclusive,
    str: params.str
  });
  if (closeIdx >= params.str.length || params.str[closeIdx] !== '}') {
    if (params.throwOnError) {
      throw new Error(`Token '${head.tokenName}' is missing closing '}'`);
    }
    return null;
  }

  const end = closeIdx + 1;
  return {
    end,
    formatText: params.str.slice(objectStart, objectEndExclusive),
    raw: params.str.slice(params.start, end),
    start: params.start,
    token: head.tokenName
  };
}

function skipWhitespace(params: SkipWhitespaceParams): number {
  let i = params.start;
  while (i < params.str.length && /\s/.test(ensureNonNullable(params.str[i]))) {
    i++;
  }
  return i;
}
