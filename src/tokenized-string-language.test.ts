import { loadPrism } from '@obsidian-typings/obsidian-public-latest/implementations';
import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

vi.mock('@obsidian-typings/obsidian-public-latest/implementations', () => ({
  loadPrism: vi.fn()
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import {
  createTokenizedStringLanguageComponent,
  TOKENIZED_STRING_FORMAT_PATTERN,
  TOKENIZED_STRING_LANGUAGE
} from './tokenized-string-language.ts';

interface PrismLike {
  languages: Record<string, unknown>;
}

interface PrismTokenWithInside {
  inside: unknown;
  pattern: RegExp;
}

interface PrismTokenWithNestedInside {
  inside: Record<string, PrismTokenWithInside | undefined>;
  pattern: RegExp;
}

type RegisteredGrammar = Record<string, PrismTokenWithNestedInside | undefined>;

const mockLoadPrism = vi.mocked(loadPrism);

/**
 * Creates the Prism module the mocked `loadPrism` resolves with.
 *
 * Deliberately a plain object rather than a `strictProxy`: `SyntaxHighlightingComponent` READS
 * `prism.languages[language]` before writing it (it restores the previous grammar on unload), and a strict
 * proxy throws on an absent key — so proxying it would fail the registration it is meant to observe.
 *
 * @param isJavascriptRegistered - Whether the built-in `javascript` grammar the factory nests is registered.
 * @returns The Prism-like module.
 */
function createPrism(isJavascriptRegistered: boolean): PrismLike {
  return {
    languages: isJavascriptRegistered ? { javascript: { keyword: /\bif\b/ } } : {}
  };
}

function isWholeMatch(pattern: RegExp, text: string): boolean {
  return new RegExp(`^(?:${pattern.source})$`).test(text);
}

async function registerGrammar(prism: PrismLike): Promise<RegisteredGrammar> {
  mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
  const component = createTokenizedStringLanguageComponent();
  component.load();
  await component.onloadAsync();
  return castTo<RegisteredGrammar>(prism.languages[TOKENIZED_STRING_LANGUAGE]);
}

describe('tokenized-string language', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should keep the language id the settings tab highlights with', () => {
    expect(TOKENIZED_STRING_LANGUAGE).toBe('custom-attachment-location-tokenized-string');
  });

  it('should throw when the javascript language is not available', async () => {
    const prism = createPrism(false);
    await expect(registerGrammar(prism)).rejects.toThrow('Prism language "javascript" is not registered.');
    expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeUndefined();
  });

  it('should nest the javascript grammar into the format half', async () => {
    const prism = createPrism(true);
    const grammar = await registerGrammar(prism);
    expect(grammar['expressionWithFormat']?.inside['format']?.inside).toBe(prism.languages['javascript']);
  });

  it('should anchor every part inside a placeholder with a format, so an object format is never split', async () => {
    const grammar = await registerGrammar(createPrism(true));
    const inside = grammar['expressionWithFormat']?.inside ?? {};
    expect(Object.keys(inside)).toStrictEqual(['prefix', 'token', 'formatDelimiter', 'format', 'scalarFormat', 'suffix']);
    for (const key of ['prefix', 'token', 'formatDelimiter', 'format', 'scalarFormat']) {
      expect(inside[key]?.pattern.source.startsWith('^'), key).toBe(true);
    }
    expect(inside['suffix']?.pattern.source.endsWith('$')).toBe(true);
  });

  it('should add the two path tokens', async () => {
    const grammar = await registerGrammar(createPrism(true));
    expect(grammar['important']).toBeDefined();
    expect(grammar['operator']).toBeDefined();
  });

  it.each([
    '{{date:YYYY-MM-DD}}',
    '{{date:{momentJsFormat:\'YYYY\'}}}',
    '{{prompt:{defaultValueTemplate:\'{{originalAttachmentFileName}}\'}}}',
    '{{prompt:{defaultValueTemplate:\'{{date:{momentJsFormat:"YYYY"}}}\'}}}'
  ])('should match the whole of %s as one token with a format', async (text) => {
    const grammar = await registerGrammar(createPrism(true));
    const pattern = grammar['expressionWithFormat']?.pattern;
    expect(pattern).toBeDefined();
    expect(isWholeMatch(castTo<RegExp>(pattern), text)).toBe(true);
  });

  it('should match a token without a format', async () => {
    const grammar = await registerGrammar(createPrism(true));
    expect(isWholeMatch(castTo<RegExp>(grammar['expression']?.pattern), '{{noteFileName}}')).toBe(true);
  });

  it('should not match the retired dollar-brace syntax', async () => {
    const grammar = await registerGrammar(createPrism(true));
    // eslint-disable-next-line no-template-curly-in-string -- The retired plugin token syntax, not a JS template literal.
    expect(castTo<RegExp>(grammar['expression']?.pattern).test('${noteFileName}')).toBe(false);
  });

  it('should take a scalar format as text free of braces', () => {
    expect(TOKENIZED_STRING_FORMAT_PATTERN.exec('YYYY-MM-DD}}')?.[0]).toBe('YYYY-MM-DD');
  });

  it('should take an object format up to its own closing brace', () => {
    expect(TOKENIZED_STRING_FORMAT_PATTERN.exec('{a:{b:1}}}}')?.[0]).toBe('{a:{b:1}}');
  });
});
