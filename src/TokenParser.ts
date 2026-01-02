import { parseExpressionAt } from 'acorn';
import { parse } from 'json5';

export interface ScannedToken {
  end: number;
  formatText: null | string;
  raw: string;
  start: number;
  token: string;
}

const TOKEN_HEAD_REGEXP = /\$\{\s*(?<Token>[a-zA-Z0-9_]+)\s*(?<Colon>:\s*)?/y;

export function parseFormatObject(formatText: string, tokenName: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = parse(formatText);
  } catch (e) {
    throw new Error(`Invalid JSON5: ${(e as Error).message}`);
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Format for token '${tokenName}' must be a JSON5 object`);
  }
  return parsed as Record<string, unknown>;
}

export function scanTokens(str: string, options?: { throwOnError?: boolean }): ScannedToken[] {
  const throwOnError = options?.throwOnError ?? true;
  const tokens: ScannedToken[] = [];

  for (const m of str.matchAll(/\$\{/g)) {
    const start = m.index;
    const token = parseTokenAt(str, start, throwOnError);
    if (token) {
      tokens.push(token);
    }
  }

  return tokens;
}

function parseHeadAt(
  str: string,
  start: number,
  throwOnError: boolean
): { hasColon: boolean; indexAfterHead: number; tokenName: string } | null {
  TOKEN_HEAD_REGEXP.lastIndex = start;
  const head = TOKEN_HEAD_REGEXP.exec(str);
  if (!head) {
    if (throwOnError) {
      throw new Error('Invalid token start');
    }
    return null;
  }

  const tokenName = (head.groups?.['Token'] ?? '').trim();
  if (!tokenName) {
    if (throwOnError) {
      throw new Error('Empty token name');
    }
    return null;
  }

  return {
    hasColon: Boolean(head.groups?.['Colon']),
    indexAfterHead: TOKEN_HEAD_REGEXP.lastIndex,
    tokenName
  };
}

function parseObjectExpressionEndExclusive(
  str: string,
  objectStart: number,
  tokenName: string,
  throwOnError: boolean
): null | number {
  try {
    const node = parseExpressionAt(str, objectStart, { ecmaVersion: 'latest' });
    if (node.type !== 'ObjectExpression') {
      throw new Error(`Expected object literal, got ${node.type}`);
    }
    return node.end;
  } catch (e) {
    if (throwOnError) {
      throw new Error(`Invalid JSON5 object for token '${tokenName}': ${(e as Error).message}`);
    }
    return null;
  }
}

function parseTokenAt(str: string, start: number, throwOnError: boolean): null | ScannedToken {
  const head = parseHeadAt(str, start, throwOnError);
  if (!head) {
    return null;
  }

  // No format -> must close with `}`
  if (!head.hasColon) {
    const closeIdx = skipWhitespace(str, head.indexAfterHead);
    if (closeIdx >= str.length || str[closeIdx] !== '}') {
      if (throwOnError) {
        throw new Error(`Token '${head.tokenName}' is missing closing '}'`);
      }
      return null;
    }

    const end = closeIdx + 1;
    return {
      end,
      formatText: null,
      raw: str.slice(start, end),
      start,
      token: head.tokenName
    };
  }

  // Format part: must be JSON5 object `{...}`
  const objectStart = head.indexAfterHead;
  if (objectStart >= str.length || str[objectStart] !== '{') {
    if (throwOnError) {
      throw new Error(`Token '${head.tokenName}' format must be a JSON5 object starting with '{'`);
    }
    return null;
  }

  const objectEndExclusive = parseObjectExpressionEndExclusive(
    str,
    objectStart,
    head.tokenName,
    throwOnError
  );
  if (objectEndExclusive === null) {
    return null;
  }

  const closeIdx = skipWhitespace(str, objectEndExclusive);
  if (closeIdx >= str.length || str[closeIdx] !== '}') {
    if (throwOnError) {
      throw new Error(`Token '${head.tokenName}' is missing closing '}'`);
    }
    return null;
  }

  const end = closeIdx + 1;
  return {
    end,
    formatText: str.slice(objectStart, objectEndExclusive),
    raw: str.slice(start, end),
    start,
    token: head.tokenName
  };
}

function skipWhitespace(str: string, start: number): number {
  let i = start;
  while (i < str.length && /\s/.test(str[i] ?? '')) {
    i++;
  }
  return i;
}

// ScanTokens is declared above (export order).
