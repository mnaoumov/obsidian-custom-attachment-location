import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({
  value: z.string().optional().default('default-value')
});
type Format = z.infer<typeof formatSchema>;

class TestToken extends TokenBase<Format> {
  public constructor() {
    super('test', formatSchema);
  }

  protected override evaluateImpl(_ctx: TokenEvaluatorContext, format: Format): string {
    return format.value;
  }
}

const noDefaultFormatSchema = z.strictObject({
  value: z.string()
});
type NoDefaultFormat = z.infer<typeof noDefaultFormatSchema>;

class NoDefaultToken extends TokenBase<NoDefaultFormat> {
  public constructor() {
    super('noDefault', noDefaultFormatSchema);
  }

  protected override evaluateImpl(_ctx: TokenEvaluatorContext, format: NoDefaultFormat): string {
    return format.value;
  }
}

function createContext(format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format
  });
}

describe('TokenBase', () => {
  it('should expose its name', () => {
    const token = new TestToken();
    expect(token.name).toBe('test');
  });

  it('should use the default format when context format is null', () => {
    const token = new TestToken();
    const result = token.evaluate(createContext(null));
    expect(result).toBe('default-value');
  });

  it('should parse the provided format', () => {
    const token = new TestToken();
    const result = token.evaluate(createContext({ value: 'custom' }));
    expect(result).toBe('custom');
  });

  it('should throw when the provided format is invalid', () => {
    const token = new TestToken();
    expect(() => token.evaluate(createContext({ value: 123 }))).toThrow();
  });

  it('should throw when default format is not supported', () => {
    const token = new NoDefaultToken();
    expect(() => token.evaluate(createContext(null))).toThrow('Token noDefault does not support default format.');
  });
});
