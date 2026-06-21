import { loadPrism } from '@obsidian-typings/obsidian-public-latest/implementations';
import { invokeAsyncSafely } from 'obsidian-dev-utils/async';
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

/*
 * Deliberate exception to the "reuse the real obsidian-dev-utils helpers" rule:
 * invokeAsyncSafely is stubbed ONLY so the fire-and-forget initPrism scheduling
 * done inside the real ComponentEx.onload override becomes awaitable here. The
 * real ComponentEx base class and its real load()/unload()/register() lifecycle
 * are used unmocked.
 */
vi.mock('obsidian-dev-utils/async', () => ({
  invokeAsyncSafely: vi.fn()
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
const mockInvokeAsyncSafely = vi.mocked(invokeAsyncSafely);

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
    it('should schedule initPrism when loaded through the real lifecycle', () => {
      component.load();
      expect(mockInvokeAsyncSafely).toHaveBeenCalledOnce();
    });

    it('should run initPrism when the scheduled callback is invoked', async () => {
      let scheduled: Parameters<typeof invokeAsyncSafely>[0] | undefined;
      mockInvokeAsyncSafely.mockImplementation((fn) => {
        scheduled = fn;
      });
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(createPrism(true)));
      component.load();
      await scheduled?.();
      expect(mockLoadPrism).toHaveBeenCalledOnce();
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
