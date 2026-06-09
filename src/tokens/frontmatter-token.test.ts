import type {
  App,
  CachedMetadata,
  TFile
} from 'obsidian';

import {
  castTo,
  getNestedPropertyValue
} from 'obsidian-dev-utils/object-utils';
import { getFileOrNull } from 'obsidian-dev-utils/obsidian/file-system';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { FrontmatterToken } from './frontmatter-token.ts';

vi.mock('obsidian-dev-utils/object-utils', async (importOriginal) => {
  const actual = await importOriginal<typeof import('obsidian-dev-utils/object-utils')>();
  return {
    ...actual,
    getNestedPropertyValue: vi.fn<(obj: object, path: string) => unknown>()
  };
});

vi.mock('obsidian-dev-utils/obsidian/file-system', () => ({
  getFileOrNull: vi.fn<(app: App, pathOrFile: null | string) => null | TFile>()
}));

function createContext(getFileCache: (file: TFile) => CachedMetadata | null): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    app: castTo<App>({
      metadataCache: castTo<App['metadataCache']>({
        getFileCache: vi.fn(getFileCache)
      })
    }),
    format: { key: 'title' },
    noteFilePath: 'note.md'
  });
}

beforeEach(() => {
  vi.mocked(getFileOrNull).mockReset();
  vi.mocked(getNestedPropertyValue).mockReset();
});

describe('FrontmatterToken', () => {
  it('should be named frontmatter', () => {
    const token = new FrontmatterToken();
    expect(token.name).toBe('frontmatter');
  });

  it('should return an empty string when the note file does not exist', () => {
    vi.mocked(getFileOrNull).mockReturnValue(null);
    const token = new FrontmatterToken();
    const result = token.evaluate(createContext(() => null));
    expect(result).toBe('');
  });

  it('should return an empty string when there is no frontmatter', () => {
    vi.mocked(getFileOrNull).mockReturnValue(strictProxy<TFile>({}));
    const token = new FrontmatterToken();
    const result = token.evaluate(createContext(() => castTo<CachedMetadata>({})));
    expect(result).toBe('');
  });

  it('should return the stringified frontmatter value for the key', () => {
    vi.mocked(getFileOrNull).mockReturnValue(strictProxy<TFile>({}));
    vi.mocked(getNestedPropertyValue).mockReturnValue('My Title');
    const token = new FrontmatterToken();
    const result = token.evaluate(createContext(() =>
      strictProxy<CachedMetadata>({
        frontmatter: { title: 'My Title' }
      })
    ));
    expect(result).toBe('My Title');
    expect(getNestedPropertyValue).toHaveBeenCalledWith({ title: 'My Title' }, 'title');
  });

  it('should return an empty string when the frontmatter value is missing', () => {
    vi.mocked(getFileOrNull).mockReturnValue(strictProxy<TFile>({}));
    vi.mocked(getNestedPropertyValue).mockReturnValue(undefined);
    const token = new FrontmatterToken();
    const result = token.evaluate(createContext(() =>
      strictProxy<CachedMetadata>({
        frontmatter: { other: 1 }
      })
    ));
    expect(result).toBe('');
  });
});
