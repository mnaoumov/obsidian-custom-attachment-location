import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { NoteFilePathToken } from './note-file-path-token.ts';

function createContext(noteFilePath: string): TokenEvaluatorContext {
  return strictProxy<TokenEvaluatorContext>({
    format: null,
    noteFilePath
  });
}

describe('NoteFilePathToken', () => {
  it('should be named noteFilePath', () => {
    const token = new NoteFilePathToken();
    expect(token.name).toBe('noteFilePath');
  });

  it('should return the note file path', () => {
    const token = new NoteFilePathToken();
    const result = token.evaluate(createContext('folder/note.md'));
    expect(result).toBe('folder/note.md');
  });
});
