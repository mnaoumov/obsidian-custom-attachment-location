import type { Promisable } from 'type-fest';

import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  afterEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  getRangeStr,
  RandomToken
} from './random-token.ts';

interface EvaluateImplFormat {
  digits: boolean;
  length: number;
  letterCase: 'lower' | 'mixed' | 'upper';
  letters: boolean;
}

class TestableRandomToken extends RandomToken {
  public callEvaluateImpl(ctx: TokenEvaluatorContext, format: EvaluateImplFormat): Promisable<string> {
    return this.evaluateImpl(ctx, format);
  }
}

function createContext(format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('RandomToken', () => {
  it('should be named random', () => {
    const token = new RandomToken();
    expect(token.name).toBe('random');
  });

  it('should generate uppercase letters and digits by default with length 1', () => {
    const token = new RandomToken();
    const result = token.evaluate(createContext(null));
    expect(result).toMatch(/^[0-9A-Z]$/);
  });

  it('should generate only digits when letters are disabled', () => {
    const token = new RandomToken();
    const result = token.evaluate(createContext({ length: 10, letters: false }));
    expect(result).toMatch(/^[0-9]{10}$/);
  });

  it('should generate only lowercase letters', () => {
    const token = new RandomToken();
    const result = token.evaluate(createContext({ digits: false, length: 10, letterCase: 'lower' }));
    expect(result).toMatch(/^[a-z]{10}$/);
  });

  it('should generate mixed-case letters', () => {
    const token = new RandomToken();
    const result = token.evaluate(createContext({ digits: false, length: 20, letterCase: 'mixed' }));
    expect(result).toMatch(/^[a-zA-Z]{20}$/);
  });

  it('should generate uppercase letters', () => {
    const token = new RandomToken();
    const result = token.evaluate(createContext({ digits: false, length: 10, letterCase: 'upper' }));
    expect(result).toMatch(/^[A-Z]{10}$/);
  });

  it('should fall back to an empty character when the symbol pool is empty', () => {
    const token = new RandomToken();
    const result = token.evaluate(createContext({ digits: false, length: 5, letters: false }));
    expect(result).toBe('');
  });

  it('should reject an invalid letter case through the schema', () => {
    const token = new RandomToken();
    const format = castTo<TokenEvaluatorContext['format']>({ digits: false, letterCase: 'invalid', letters: true });
    expect(() => token.evaluate(createContext(format))).toThrow();
  });

  it('should throw on an invalid letter case reaching the evaluator directly', () => {
    const token = new TestableRandomToken();
    const format = castTo<EvaluateImplFormat>({ digits: false, length: 1, letterCase: 'invalid', letters: true });
    expect(() => token.callEvaluateImpl(createContext(null), format)).toThrow('Invalid letter case: invalid');
  });
});

describe('getRangeStr', () => {
  it('should build an inclusive character range', () => {
    expect(getRangeStr('a', 'e')).toBe('abcde');
  });

  it('should throw when the from value is not a single character', () => {
    expect(() => getRangeStr('ab', 'z')).toThrow('Range must be from-to a single character: ab to z');
  });

  it('should throw when the to value is not a single character', () => {
    expect(() => getRangeStr('a', 'yz')).toThrow('Range must be from-to a single character: a to yz');
  });
});
