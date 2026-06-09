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

vi.mock('obsidian-dev-utils/async', () => ({
  invokeAsyncSafely: vi.fn()
}));

const onloadCalls: number[] = [];

vi.mock('obsidian-dev-utils/obsidian/components/component-ex', () => ({
  ComponentEx: class {
    public register = vi.fn<(cb: () => void) => void>();

    public onload(): void {
      onloadCalls.push(1);
    }
  }
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import {
  PrismComponent,
  TOKENIZED_STRING_LANGUAGE
} from './prism-component.ts';

interface PrismComponentPrivate {
  initPrism(): Promise<void>;
  register: ReturnType<typeof vi.fn<(cb: () => void) => void>>;
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
    onloadCalls.length = 0;
    component = new PrismComponent();
  });

  it('should export the tokenized string language id', () => {
    expect(TOKENIZED_STRING_LANGUAGE).toBe('custom-attachment-location-tokenized-string');
  });

  describe('onload', () => {
    it('should call super.onload and schedule initPrism', () => {
      component.onload();
      expect(onloadCalls).toHaveLength(1);
      expect(mockInvokeAsyncSafely).toHaveBeenCalledOnce();
    });

    it('should run initPrism when the scheduled callback is invoked', async () => {
      let scheduled: Parameters<typeof invokeAsyncSafely>[0] | undefined;
      mockInvokeAsyncSafely.mockImplementation((fn) => {
        scheduled = fn;
      });
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(createPrism(true)));
      component.onload();
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
      expect(asPrivate(component).register).not.toHaveBeenCalled();
    });

    it('should register the tokenized string language and a cleanup callback', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      await asPrivate(component).initPrism();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeDefined();
      expect(asPrivate(component).register).toHaveBeenCalledOnce();
    });

    it('should delete the tokenized string language when the cleanup callback runs', async () => {
      const prism = createPrism(true);
      mockLoadPrism.mockResolvedValue(castTo<Awaited<ReturnType<typeof loadPrism>>>(prism));
      await asPrivate(component).initPrism();
      const registerMock = asPrivate(component).register;
      const cleanup = registerMock.mock.calls[0]?.[0];
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeDefined();
      cleanup?.();
      expect(prism.languages[TOKENIZED_STRING_LANGUAGE]).toBeUndefined();
    });
  });
});
