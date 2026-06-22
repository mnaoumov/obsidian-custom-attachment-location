import { printError } from 'obsidian-dev-utils/error';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';
import type { TokenEvaluator } from './custom-token.ts';

import { CustomToken } from './custom-token.ts';

vi.mock('obsidian-dev-utils/error', async (importOriginal) => {
  const actual = await importOriginal<typeof import('obsidian-dev-utils/error')>();
  return {
    ...actual,
    printError: vi.fn<typeof printError>()
  };
});

function createContext(format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return strictProxy<TokenEvaluatorContext>({
    format
  });
}

afterEach(() => {
  vi.mocked(printError).mockReset();
});

describe('CustomToken', () => {
  it('should use the provided name', () => {
    const evaluator = vi.fn<TokenEvaluator>();
    const token = new CustomToken('myToken', evaluator);
    expect(token.name).toBe('myToken');
  });

  it('should delegate evaluation to the evaluator', async () => {
    const evaluator = vi.fn<TokenEvaluator>(() => 'evaluated');
    const token = new CustomToken('myToken', evaluator);
    const ctx = createContext({ extra: true });
    const result = await token.evaluate(ctx);
    expect(result).toBe('evaluated');
    expect(evaluator).toHaveBeenCalledWith(ctx);
  });

  it('should accept any loose format object', async () => {
    const evaluator = vi.fn<TokenEvaluator>(() => 'ok');
    const token = new CustomToken('myToken', evaluator);
    const result = await token.evaluate(createContext({ anything: 'goes', nested: { value: 1 } }));
    expect(result).toBe('ok');
  });
});

describe('CustomToken.parse', () => {
  it('should register the custom tokens declared in the string', async () => {
    const tokens = CustomToken.parse(`
      registerCustomToken('foo', () => 'fooValue');
      registerCustomToken('bar', () => 'barValue');
    `);

    expect(tokens).not.toBeNull();
    expect(tokens).toHaveLength(2);
    const [fooToken, barToken] = tokens ?? [];
    expect(fooToken?.name).toBe('foo');
    expect(barToken?.name).toBe('bar');
    expect(await fooToken?.evaluate(createContext(null))).toBe('fooValue');
    expect(await barToken?.evaluate(createContext(null))).toBe('barValue');
    expect(printError).not.toHaveBeenCalled();
  });

  it('should return an empty array when no tokens are registered', () => {
    const tokens = CustomToken.parse('');
    expect(tokens).toEqual([]);
    expect(printError).not.toHaveBeenCalled();
  });

  it('should print the error and return null when registration throws', () => {
    const tokens = CustomToken.parse('this is not valid javascript (');
    expect(tokens).toBeNull();
    expect(printError).toHaveBeenCalledTimes(1);
    const [errorArg] = vi.mocked(printError).mock.calls[0] ?? [];
    expect(errorArg).toBeInstanceOf(Error);
    if (!(errorArg instanceof Error)) {
      throw new Error('Expected the printed error to be an Error instance.');
    }
    expect(errorArg.message).toBe('Error registering custom tokens');
    expect(errorArg.cause).toBeInstanceOf(Error);
  });
});
