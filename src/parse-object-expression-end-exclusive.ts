import { parseExpressionAt } from 'acorn';

interface ParseObjectExpressionEndExclusiveParams {
  readonly objectStart: number;
  readonly str: string;
  readonly throwOnError: boolean;
  readonly tokenName: string;
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
