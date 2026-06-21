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
  PrismComponent,
  TOKENIZED_STRING_LANGUAGE
} from './prism-component.ts';

interface PrismComponentPrivate {
  initPrism(): Promise<void>;
}

interface PrismLike {
  languages: Record<string, unknown>;
}

const mockLoadPrism = vi.mocked(loadPrism);

function asPrivate(component: PrismComponent): PrismComponentPrivate {
  return castTo<PrismComponentPrivate>(component);
}

function createPrism(withJavascript: boolean): PrismLike {
  return {
    languages: withJavascript ? { javascript: { keyword: /\bif\b/ } } : {}
  };
}

describe('PrismComponent', () => {
  let component: PrismComponent;

  beforeEach(() => {
    vi.clearAllMocks();
    component = new PrismComponent();
  });

  it('should export the tokenized string language id', () => {
    expect(TOKENIZED_STRING_LANGUAGE).toBe('custom-attachment-location-tokenized-string');
  });

  describe('onload', () => {
    it('should schedule initPrism when loaded through the real lifecycle', async () => {
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(createPrism(true)));
      component.load();
      // The real onload schedules initPrism via the real invokeAsyncSafely (fire-and-forget).
      // Drain the tracked operation, then assert it ran.
      await waitForAllAsyncOperations();
      expect(mockLoadPrism).toHaveBeenCalledOnce();
    });

    it('should run initPrism when the scheduled callback is invoked', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      component.load();
      // Drain the fire-and-forget initPrism scheduled by the real lifecycle, then assert its effect.
      await waitForAllAsyncOperations();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeDefined();
    });
  });

  describe('initPrism', () => {
    it('should return early when the javascript language is not available', async () => {
      const prism = createPrism(false);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      await asPrivate(component).initPrism();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeUndefined();
    });

    it('should register the tokenized string language', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      await asPrivate(component).initPrism();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeDefined();
    });

    it('should delete the tokenized string language when the component is unloaded', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      component.load();
      await asPrivate(component).initPrism();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeDefined();
      component.unload();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeUndefined();
    });
  });
});
