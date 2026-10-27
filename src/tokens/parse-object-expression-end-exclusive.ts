import { parseExpressionAt } from 'acorn';

interface ParseObjectExpressionEndExclusiveParams {
  readonly objectStart: number;
  readonly string: string;
  readonly throwOnError: boolean;
  readonly tokenName: string;
}

export function parseObjectExpressionEndExclusive(params: ParseObjectExpressionEndExclusiveParams): null | number {
  try {
    const node = parseExpressionAt(params.string, params.objectStart, { ecmaVersion: 'latest' });
    if (node.type !== 'ObjectExpression') {
      throw new Error(`Expected object literal, got ${node.type}`);
    }
    return node.end;
  } catch (error) {
    if (params.throwOnError) {
      throw new Error(`Invalid JSON5 object for token '${params.tokenName}'`, { cause: error });
    }
    return null;
  }
}
