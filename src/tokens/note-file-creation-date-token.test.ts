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
import { NoteFileCreationDateToken } from './note-file-creation-date-token.ts';

vi.mock('obsidian-dev-utils/obsidian/file-system', () => ({
  getFile: vi.fn<(app: App, pathOrFile: string) => TFile>()
}));

const CTIME = Date.UTC(2020, 0, 2, 3, 4, 5);

const app = castTo<App>({});

function createContext(format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    app,
    format,
    noteFilePath: 'note.md'
  });
}

describe('NoteFileCreationDateToken', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should be named noteFileCreationDate', () => {
    const token = new NoteFileCreationDateToken();
    expect(token.name).toBe('noteFileCreationDate');
  });

  it('should format the note file creation date', () => {
    const file = strictProxy<TFile>({
      stat: strictProxy<TFile['stat']>({ ctime: CTIME })
    });
    vi.mocked(getFile).mockReturnValue(file);

    const token = new NoteFileCreationDateToken();
    const result = token.evaluate(createContext({ momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe(moment(CTIME).format('YYYY-MM-DD'));
    expect(getFile).toHaveBeenCalledWith(app, 'note.md');
  });

  it('should format the current date for the dummy path', () => {
    vi.spyOn(Date, 'now').mockReturnValue(CTIME);
    vi.mocked(getFile).mockClear();

    const token = new NoteFileCreationDateToken();
    const context = createContext({ momentJsFormat: 'YYYY-MM-DD' });
    context.noteFilePath = DUMMY_PATH;
    const result = token.evaluate(context);
    expect(result).toBe(moment(CTIME).format('YYYY-MM-DD'));
    expect(getFile).not.toHaveBeenCalled();
  });
});
