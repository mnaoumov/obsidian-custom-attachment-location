import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { NoteFileNameToken } from './note-file-name-token.ts';

function createContext(noteFileName: string, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format,
    noteFileName
  });
}

describe('NoteFileNameToken', () => {
  it('should be named noteFileName', () => {
    const token = new NoteFileNameToken();
    expect(token.name).toBe('noteFileName');
  });

  it('should return the note file name unchanged by default', () => {
    const token = new NoteFileNameToken();
    const result = token.evaluate(createContext('My Note', null));
    expect(result).toBe('My Note');
  });

  it('should apply the string format', () => {
    const token = new NoteFileNameToken();
    const result = token.evaluate(createContext('My Note', { case: 'upper' }));
    expect(result).toBe('MY NOTE');
  });
});
