import type {
  App,
  CachedMetadata,
  HeadingCache
} from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { getCacheSafe } from 'obsidian-dev-utils/obsidian/metadata-cache';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { HeadingToken } from './heading-token.ts';

vi.mock('obsidian-dev-utils/obsidian/metadata-cache', () => ({
  getCacheSafe: vi.fn<(app: App, fileOrPath: string) => Promise<CachedMetadata | null>>()
}));

const app = castTo<App>({});

function createContext(cursorLine: null | number, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    app,
    cursorLine,
    format,
    noteFilePath: 'note.md',
    pluginSettingsComponent: castTo<PluginSettingsComponent>({
      replaceSpecialCharacters: vi.fn((str: string) => `clean:${str}`)
    })
  });
}

function createHeading(level: number, line: number, heading: string): HeadingCache {
  return strictProxy<HeadingCache>({
    heading,
    level,
    position: strictProxy<HeadingCache['position']>({
      start: strictProxy<HeadingCache['position']['start']>({ line })
    })
  });
}

beforeEach(() => {
  vi.mocked(getCacheSafe).mockReset();
});

describe('HeadingToken', () => {
  it('should be named heading', () => {
    const token = new HeadingToken();
    expect(token.name).toBe('heading');
  });

  it('should return an empty (cleaned) heading when there is no cursor line', async () => {
    const token = new HeadingToken();
    const result = await token.evaluate(createContext(null, null));
    expect(result).toBe('clean:');
    expect(getCacheSafe).not.toHaveBeenCalled();
  });

  it('should return an empty (cleaned) heading when there are no headings in the cache', async () => {
    vi.mocked(getCacheSafe).mockResolvedValue(castTo<CachedMetadata>({}));
    const token = new HeadingToken();
    const result = await token.evaluate(createContext(10, null));
    expect(result).toBe('clean:');
  });

  it('should return the latest heading of any level before the cursor by default', async () => {
    vi.mocked(getCacheSafe).mockResolvedValue(strictProxy<CachedMetadata>({
      headings: [
        createHeading(1, 0, 'Top'),
        createHeading(2, 5, 'Section'),
        createHeading(2, 50, 'After cursor')
      ]
    }));
    const token = new HeadingToken();
    const result = await token.evaluate(createContext(10, null));
    expect(result).toBe('clean:Section');
  });

  it('should return the latest heading of the requested level', async () => {
    vi.mocked(getCacheSafe).mockResolvedValue(strictProxy<CachedMetadata>({
      headings: [
        createHeading(1, 0, 'First H1'),
        createHeading(1, 3, 'Second H1'),
        createHeading(2, 5, 'Sub')
      ]
    }));
    const token = new HeadingToken();
    const result = await token.evaluate(createContext(10, { level: '1' }));
    expect(result).toBe('clean:Second H1');
  });

  it('should not update a heading level for an earlier line than already recorded', async () => {
    vi.mocked(getCacheSafe).mockResolvedValue(strictProxy<CachedMetadata>({
      headings: [
        createHeading(1, 5, 'Later'),
        createHeading(1, 2, 'Earlier')
      ]
    }));
    const token = new HeadingToken();
    const result = await token.evaluate(createContext(10, { level: '1' }));
    expect(result).toBe('clean:Later');
  });

  it('should keep the latest any-level heading when a later-processed heading is on an earlier line', async () => {
    vi.mocked(getCacheSafe).mockResolvedValue(strictProxy<CachedMetadata>({
      headings: [
        createHeading(2, 5, 'Deep section'),
        createHeading(1, 2, 'Early top')
      ]
    }));
    const token = new HeadingToken();
    const result = await token.evaluate(createContext(10, null));
    expect(result).toBe('clean:Deep section');
  });

  it('should return an empty heading when no heading matches the requested level', async () => {
    vi.mocked(getCacheSafe).mockResolvedValue(strictProxy<CachedMetadata>({
      headings: [
        createHeading(1, 0, 'Top')
      ]
    }));
    const token = new HeadingToken();
    const result = await token.evaluate(createContext(10, { level: '3' }));
    expect(result).toBe('clean:');
  });
});
