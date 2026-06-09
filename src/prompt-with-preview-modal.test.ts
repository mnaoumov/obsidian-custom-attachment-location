import type {
  App,
  TFile
} from 'obsidian';
import type { StrictProxyPartial } from 'obsidian-dev-utils/strict-proxy';

import { noopAsync } from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { TokenEvaluatorContext } from './token-evaluator-context.ts';

import { translationsMap } from './i18n/locales/translations-map.ts';

interface CapturedButton {
  click(): void;
  isDisabled: boolean;
  text: string;
}

interface CapturedTextComponent {
  changeValue(value: string): void;
  inputEl: HTMLInputElement;
  value: string;
}

type EmbedByExtension = Partial<App['embedRegistry']['embedByExtension']>;

type EmbedCreator = NonNullable<App['embedRegistry']['embedByExtension'][string]>;

const captured = {
  buttons: [] as CapturedButton[],
  textComponents: [] as CapturedTextComponent[]
};

const hoisted = vi.hoisted(() => ({
  embedComponent: {
    load: vi.fn(),
    loadFile: vi.fn(),
    unload: vi.fn()
  },
  mockTrashSafe: vi.fn((..._args: unknown[]): Promise<void> => noopAsync())
}));

vi.mock('obsidian-dev-utils/obsidian/plugin/plugin-context', () => ({
  addPluginCssClasses: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/vault', () => ({
  trashSafe: (...args: unknown[]): Promise<void> => hoisted.mockTrashSafe(...args)
}));

vi.mock('obsidian', async (importOriginal) => {
  const original = await importOriginal<typeof import('obsidian')>();

  function noopClick(_event: Event): void {
    // Placeholder until a real handler is registered.
  }

  class MockButtonComponent {
    private clickHandler: (event: Event) => void = noopClick;
    private readonly entry: CapturedButton;

    public constructor(_containerEl: HTMLElement) {
      this.entry = {
        click: (): void => {
          this.clickHandler(new Event('click'));
        },
        isDisabled: false,
        text: ''
      };
      captured.buttons.push(this.entry);
    }

    public onClick(handler: (event: Event) => void): this {
      this.clickHandler = handler;
      return this;
    }

    public setButtonText(value: string): this {
      this.entry.text = value;
      return this;
    }

    public setClass(): this {
      return this;
    }

    public setCta(): this {
      return this;
    }

    public setDisabled(value: boolean): this {
      this.entry.isDisabled = value;
      return this;
    }
  }

  class MockTextComponent {
    public inputEl: HTMLInputElement;
    public constructor(containerEl: HTMLElement) {
      const inputEl = containerEl.createEl('input');
      this.inputEl = inputEl;
      captured.textComponents.push({
        changeValue: (value: string): void => {
          inputEl.value = value;
          this.changeHandler(value);
        },
        inputEl,
        get value(): string {
          return inputEl.value;
        }
      });
    }

    public onChange(handler: (value: string) => void): this {
      this.changeHandler = handler;
      return this;
    }

    public setPlaceholder(value: string): this {
      this.inputEl.placeholder = value;
      return this;
    }

    public setValue(value: string): this {
      this.inputEl.value = value;
      return this;
    }

    private changeHandler: (value: string) => void = () => undefined;
  }

  return {
    ...original,
    ButtonComponent: MockButtonComponent,
    TextComponent: MockTextComponent
  };
});

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import { promptWithPreview } from './prompt-with-preview-modal.ts';

function createApp(overrides: StrictProxyPartial<App>): App {
  return strictProxy<App>({
    embedRegistry: createEmbedRegistry({}),
    vault: castTo<App['vault']>({
      createBinary: vi.fn((path: string): Promise<TFile> => Promise.resolve(strictProxy<TFile>({ path })))
    }),
    ...overrides
  });
}

function createCtx(overrides: StrictProxyPartial<TokenEvaluatorContext>): TokenEvaluatorContext {
  return strictProxy<TokenEvaluatorContext>({
    app: createApp({}),
    attachmentFileContent: undefined,
    fillTemplate: vi.fn((template: string): Promise<string> => Promise.resolve(template)),
    // eslint-disable-next-line no-template-curly-in-string -- This is a literal token template string, not a JS template literal.
    fullTemplate: 'before${token}after',
    originalAttachmentFileExtension: 'png',
    originalAttachmentFileName: 'image',
    tokenEndOffset: 13,
    tokenStartOffset: 6,
    // eslint-disable-next-line no-template-curly-in-string -- This is a literal token template string, not a JS template literal.
    tokenWithFormat: '${token}',
    ...overrides
  });
}

function createEmbedRegistry(embedByExtension: EmbedByExtension): App['embedRegistry'] {
  // A null-prototype dictionary so strictProxy does not wrap it (it only wraps plain objects),
  // Letting lookups of missing extensions return `undefined` instead of throwing.
  const dictionary = Object.assign(Object.create(null), embedByExtension);
  return castTo<App['embedRegistry']>({
    embedByExtension: dictionary
  });
}

async function flushOnOpen(): Promise<void> {
  for (let i = 0; i < 10; i++) {
    await noopAsync();
  }
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('promptWithPreview', () => {
  beforeEach(() => {
    captured.buttons.length = 0;
    captured.textComponents.length = 0;
    hoisted.embedComponent.load.mockClear();
    hoisted.embedComponent.loadFile.mockClear();
    hoisted.embedComponent.unload.mockClear();
    hoisted.mockTrashSafe.mockClear();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should resolve with null when closed without clicking OK', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({}),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    await vi.advanceTimersByTimeAsync(0);
    const result = await promise;
    expect(result).toBeNull();
  });

  it('should render OK, Cancel and Preview buttons', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({}),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    expect(captured.buttons.map((button) => button.text)).toStrictEqual(['OK', 'Cancel', 'Preview attachment file']);
    await vi.advanceTimersByTimeAsync(0);
    await promise;
  });

  it('should resolve with the filled template value when OK is clicked on a valid input', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({ fillTemplate: vi.fn((): Promise<string> => Promise.resolve('filled-value')) }),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    captured.buttons[0]?.click();
    const result = await promise;
    expect(result).toBe('filled-value');
  });

  it('should not resolve with the value when OK is clicked on an invalid input', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({}),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve('error'))
    });
    await flushOnOpen();
    const textComponent = captured.textComponents[0];
    textComponent?.inputEl.setCustomValidity('error');
    captured.buttons[0]?.click();
    await vi.advanceTimersByTimeAsync(0);
    const result = await promise;
    expect(result).toBeNull();
  });

  it('should resolve with the updated value when the input changes and OK is clicked', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({}),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    captured.textComponents[0]?.changeValue('updated-value');
    captured.buttons[0]?.click();
    const result = await promise;
    expect(result).toBe('updated-value');
  });

  it('should resolve with the value when Enter is pressed on a valid input', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({ fillTemplate: vi.fn((): Promise<string> => Promise.resolve('filled-value')) }),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    captured.textComponents[0]?.inputEl.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    const result = await promise;
    expect(result).toBe('filled-value');
  });

  it('should resolve with null when Escape is pressed', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({}),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    captured.textComponents[0]?.inputEl.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    const result = await promise;
    expect(result).toBeNull();
  });

  it('should ignore other keydown keys', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({}),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    captured.textComponents[0]?.inputEl.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }));
    await vi.advanceTimersByTimeAsync(0);
    const result = await promise;
    expect(result).toBeNull();
  });

  it('should disable the Preview button when there is no attachment content', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({ attachmentFileContent: undefined }),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    const previewButton = captured.buttons[2];
    expect(previewButton?.isDisabled).toBe(true);
    await vi.advanceTimersByTimeAsync(0);
    await promise;
  });

  it('should enable the Preview button when an embeddable creator and content are available', async () => {
    const embeddableCreator = vi.fn<EmbedCreator>(() => castTo<ReturnType<EmbedCreator>>(hoisted.embedComponent));
    const promise = promptWithPreview({
      ctx: createCtx({
        app: createApp({
          embedRegistry: createEmbedRegistry({ png: embeddableCreator })
        }),
        attachmentFileContent: new ArrayBuffer(8)
      }),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    expect(captured.buttons[2]?.isDisabled).toBe(false);
    await vi.advanceTimersByTimeAsync(0);
    await promise;
  });

  it('should open the preview modal and load the embed when the Preview button is clicked', async () => {
    const embeddableCreator = vi.fn<EmbedCreator>(() => castTo<ReturnType<EmbedCreator>>(hoisted.embedComponent));
    const createBinary = vi.fn((path: string): Promise<TFile> => Promise.resolve(strictProxy<TFile>({ name: 'temp', path })));
    const promise = promptWithPreview({
      ctx: createCtx({
        app: createApp({
          embedRegistry: createEmbedRegistry({ png: embeddableCreator }),
          vault: castTo<App['vault']>({ createBinary })
        }),
        attachmentFileContent: new ArrayBuffer(8)
      }),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    captured.buttons[2]?.click();
    await flushOnOpen();
    expect(embeddableCreator).toHaveBeenCalled();
    expect(hoisted.embedComponent.load).toHaveBeenCalled();
    expect(hoisted.embedComponent.loadFile).toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(0);
    await promise;
  });

  it('should not load an embed in the preview modal when there is no embeddable creator', async () => {
    const promise = promptWithPreview({
      ctx: createCtx({
        app: createApp({
          embedRegistry: createEmbedRegistry({})
        }),
        attachmentFileContent: new ArrayBuffer(8)
      }),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    captured.buttons[2]?.click();
    await flushOnOpen();
    expect(hoisted.embedComponent.load).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(0);
    await promise;
  });

  it('should unload the embed and trash the temp file when the preview modal closes', async () => {
    const embeddableCreator = vi.fn<EmbedCreator>(() => castTo<ReturnType<EmbedCreator>>(hoisted.embedComponent));
    const promise = promptWithPreview({
      ctx: createCtx({
        app: createApp({
          embedRegistry: createEmbedRegistry({ png: embeddableCreator })
        }),
        attachmentFileContent: new ArrayBuffer(8)
      }),
      defaultValue: 'default-value',
      valueValidator: vi.fn((): Promise<null | string> => Promise.resolve(null))
    });
    await flushOnOpen();
    captured.buttons[2]?.click();
    await flushOnOpen();
    await vi.advanceTimersByTimeAsync(0);
    await flushOnOpen();
    expect(hoisted.embedComponent.unload).toHaveBeenCalled();
    expect(hoisted.mockTrashSafe).toHaveBeenCalled();
    await promise;
  });
});
