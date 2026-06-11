import type {
  App,
  TFile
} from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import { getFile } from 'obsidian-dev-utils/obsidian/file-system';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { moment } from './moment-js-token-base.ts';
import { NoteFileModificationDateToken } from './note-file-modification-date-token.ts';

vi.mock('obsidian-dev-utils/obsidian/file-system', () => ({
  getFile: vi.fn<(app: App, pathOrFile: string) => TFile>()
}));

const MTIME = Date.UTC(2022, 5, 6, 7, 8, 9);

const app = castTo<App>({});

function createContext(format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    app,
    format,
    noteFilePath: 'note.md'
  });
}

describe('NoteFileModificationDateToken', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should be named noteFileModificationDate', () => {
    const token = new NoteFileModificationDateToken();
    expect(token.name).toBe('noteFileModificationDate');
  });

  it('should format the note file modification date', () => {
    const file = strictProxy<TFile>({
      stat: strictProxy<TFile['stat']>({ mtime: MTIME })
    });
    vi.mocked(getFile).mockReturnValue(file);

    const token = new NoteFileModificationDateToken();
    const result = token.evaluate(createContext({ momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe(moment(MTIME).format('YYYY-MM-DD'));
    expect(getFile).toHaveBeenCalledWith(app, 'note.md');
  });

  it('should format the current date for the dummy path', () => {
    vi.spyOn(Date, 'now').mockReturnValue(MTIME);
    vi.mocked(getFile).mockClear();

    const token = new NoteFileModificationDateToken();
    const context = createContext({ momentJsFormat: 'YYYY-MM-DD' });
    context.noteFilePath = DUMMY_PATH;
    const result = token.evaluate(context);
    expect(result).toBe(moment(MTIME).format('YYYY-MM-DD'));
    expect(getFile).not.toHaveBeenCalled();
  });
});
