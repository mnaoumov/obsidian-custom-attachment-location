import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { DateToken } from './date-token.ts';

function createContext(format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format
  });
}

describe('DateToken', () => {
  it('should be named date', () => {
    const token = new DateToken();
    expect(token.name).toBe('date');
  });

  it('should format the current time using the provided momentJsFormat', () => {
    const token = new DateToken();
    const result = token.evaluate(createContext({ momentJsFormat: '[constant]' }));
    expect(result).toBe('constant');
  });
});
