import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { NoteFolderPathToken } from './note-folder-path-token.ts';

function createContext(noteFolderPath: string): TokenEvaluatorContext {
  return strictProxy<TokenEvaluatorContext>({
    format: null,
    noteFolderPath
  });
}

describe('NoteFolderPathToken', () => {
  it('should be named noteFolderPath', () => {
    const token = new NoteFolderPathToken();
    expect(token.name).toBe('noteFolderPath');
  });

  it('should return the note folder path', () => {
    const token = new NoteFolderPathToken();
    const result = token.evaluate(createContext('a/b/c'));
    expect(result).toBe('a/b/c');
  });
});
