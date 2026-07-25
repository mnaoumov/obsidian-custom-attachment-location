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

  // Regression for issue #29: literal text must be escaped with Moment.js square brackets `[...]`.
  // Quoting does not escape it, leaving format letters (e.g. `a`, `t`) active, producing garbage like `pmt`.
  it('should treat text wrapped in square brackets as a literal, including the word "at"', () => {
    const token = new DateToken();
    const result = token.evaluate(createContext({ momentJsFormat: '[at]' }));
    expect(result).toBe('at');
  });

  it('should keep format letters active when literal text is only quoted, not bracket-escaped', () => {
    const token = new DateToken();
    // The bare `a` is the am/pm marker and `t` is a literal, so `'at'` never renders as the word "at".
    const result = token.evaluate(createContext({ momentJsFormat: 'at' }));
    expect(result).toMatch(/^(?:am|pm)t$/);
  });
});
