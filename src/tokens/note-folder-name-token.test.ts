import type { Promisable } from 'type-fest';

import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { NoteFolderNameToken } from './note-folder-name-token.ts';

interface EvaluateImplFormat {
  pick?: PickFormat;
}

interface PickFormat {
  from: 'end' | 'start';
  index: number;
}

class TestableNoteFolderNameToken extends NoteFolderNameToken {
  public callEvaluateImpl(ctx: TokenEvaluatorContext, format: EvaluateImplFormat): Promisable<string> {
    return this.evaluateImpl(ctx, castTo<Parameters<TestableNoteFolderNameToken['evaluateImpl']>[1]>(format));
  }
}

function createContext(noteFolderPath: string, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format,
    noteFolderPath
  });
}

describe('NoteFolderNameToken', () => {
  it('should be named noteFolderName', () => {
    const token = new NoteFolderNameToken();
    expect(token.name).toBe('noteFolderName');
  });

  it('should return the last folder part by default', () => {
    const token = new NoteFolderNameToken();
    const result = token.evaluate(createContext('a/b/c', null));
    expect(result).toBe('c');
  });

  it('should pick a folder part from the start', () => {
    const token = new NoteFolderNameToken();
    const result = token.evaluate(createContext('a/b/c', { pick: { from: 'start', index: 1 } }));
    expect(result).toBe('b');
  });

  it('should pick a folder part from the end', () => {
    const token = new NoteFolderNameToken();
    const result = token.evaluate(createContext('a/b/c', { pick: { from: 'end', index: 1 } }));
    expect(result).toBe('b');
  });

  it('should default the pick index to 0 from the start', () => {
    const token = new NoteFolderNameToken();
    const result = token.evaluate(createContext('a/b/c', { pick: { from: 'start' } }));
    expect(result).toBe('a');
  });

  it('should return an empty string for an out-of-range pick', () => {
    const token = new NoteFolderNameToken();
    const result = token.evaluate(createContext('a/b/c', { pick: { from: 'start', index: 10 } }));
    expect(result).toBe('');
  });

  it('should apply the string format to the picked part', () => {
    const token = new NoteFolderNameToken();
    const result = token.evaluate(createContext('a/b/c', { case: 'upper' }));
    expect(result).toBe('C');
  });

  it('should reject an invalid pick from value through the schema', () => {
    const token = new NoteFolderNameToken();
    const format = castTo<TokenEvaluatorContext['format']>({ pick: { from: 'middle', index: 0 } });
    expect(() => token.evaluate(createContext('a/b/c', format))).toThrow();
  });

  it('should throw on an invalid pick from value reaching the evaluator directly', () => {
    const token = new TestableNoteFolderNameToken();
    const format = castTo<EvaluateImplFormat>({ pick: { from: 'middle', index: 0 } });
    expect(() => token.callEvaluateImpl(createContext('a/b/c', null), format)).toThrow('Invalid pick from: middle');
  });
});
