import { loadPrism } from '@obsidian-typings/obsidian-public-latest/implementations';
import { waitForAllAsyncOperations } from 'obsidian-dev-utils/async';
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
  TOKENIZED_STRING_LANGUAGE,
  TokenizedStringLanguageComponent
} from './tokenized-string-language-component.ts';

interface PrismLike {
  languages: Record<string, unknown>;
}

interface PrismTokenWithInside {
  inside: unknown;
}

interface PrismTokenWithNestedInside {
  inside: Record<string, PrismTokenWithInside | undefined>;
}

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

describe('TokenizedStringLanguageComponent', () => {
  let component: TokenizedStringLanguageComponent;

  beforeEach(() => {
    vi.clearAllMocks();
    component = new TokenizedStringLanguageComponent();
  });

  it('should export the tokenized string language id', () => {
    expect(TOKENIZED_STRING_LANGUAGE).toBe('custom-attachment-location-tokenized-string');
  });

  describe('onload', () => {
    it('should register the language when loaded through the real lifecycle', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      component.load();
      // The real onload schedules onloadAsync via the real invokeAsyncSafely (fire-and-forget).
      // Drain the tracked operation, then assert its effect.
      await waitForAllAsyncOperations();
      expect(mockLoadPrism).toHaveBeenCalledOnce();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeDefined();
    });
  });

  describe('onloadAsync', () => {
    it('should throw when the javascript language is not available', async () => {
      const prism = createPrism(false);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      component.load();
      await expect(component.onloadAsync()).rejects.toThrow('Prism language "javascript" is not registered.');
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeUndefined();
    });

    it('should register the tokenized string language', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      component.load();
      await component.onloadAsync();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeDefined();
    });

    it('should nest the javascript grammar into the format block', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      component.load();
      await component.onloadAsync();
      const language = castTo<Record<string, PrismTokenWithNestedInside | undefined>>(
        prism.languages[TOKENIZED_STRING_LANGUAGE]
      );
      expect(language['expressionWithFormat']?.inside['format']?.inside).toBe(prism.languages['javascript']);
    });

    it('should delete the tokenized string language when the component is unloaded', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      component.load();
      await component.onloadAsync();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeDefined();
      component.unload();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeUndefined();
    });
  });
});
