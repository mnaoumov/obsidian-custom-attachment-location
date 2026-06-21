import type {
  App,
  ButtonComponent,
  TextComponent,
  TFile
} from 'obsidian';
import type { StrictProxyPartial } from 'obsidian-dev-utils/strict-proxy';

import { noopAsync } from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  ButtonComponent as ButtonComponentClass,
  TextComponent as TextComponentClass
} from 'obsidian-test-mocks/obsidian';
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
import { promptWithPreview } from './prompt-with-preview-modal.ts';

type EmbedByExtension = Partial<App['embedRegistry']['embedByExtension']>;

type EmbedCreator = NonNullable<App['embedRegistry']['embedByExtension'][string]>;

const captured = {
  buttons: [] as ButtonComponent[],
  textComponents: [] as TextComponent[]
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

const originalOnClick = ButtonComponentClass.prototype.onClick;
const originalOnChange = TextComponentClass.prototype.onChange;

function clickButton(button: ButtonComponent | undefined): void {
  if (button) {
    ButtonComponentClass.fromOriginalType2__(button).simulateClick__();
  }
}

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

function getButtonText(button: ButtonComponent): string {
  return ButtonComponentClass.fromOriginalType2__(button).buttonEl.textContent;
}

function getInputEl(textComponent: TextComponent | undefined): HTMLInputElement | undefined {
  if (!textComponent) {
    return undefined;
  }

  return TextComponentClass.fromOriginalType4__(textComponent).inputEl;
}

function isButtonDisabled(button: ButtonComponent | undefined): boolean {
  if (!button) {
    return false;
  }

  return ButtonComponentClass.fromOriginalType2__(button).disabled;
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

    // Capture the REAL test-mocks ButtonComponent/TextComponent instances created by the modal
    // (via their onClick/onChange registration) so interactions can be driven through real DOM.
    vi.spyOn(ButtonComponentClass.prototype, 'onClick').mockImplementation(function capturingOnClick(
      this: ButtonComponentClass,
      callback: (evt: MouseEvent) => unknown
    ): ButtonComponentClass {
      captured.buttons.push(castTo<ButtonComponent>(this));
      return originalOnClick.call(this, callback);
    });
    vi.spyOn(TextComponentClass.prototype, 'onChange').mockImplementation(function capturingOnChange(
      this: TextComponentClass,
      callback: (value: string) => unknown
    ): TextComponentClass {
      captured.textComponents.push(castTo<TextComponent>(this));
      return originalOnChange.call(this, callback);
    });

    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
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
    expect(captured.buttons.map(getButtonText)).toStrictEqual(['OK', 'Cancel', 'Preview attachment file']);
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
    clickButton(captured.buttons[0]);
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
    getInputEl(captured.textComponents[0])?.setCustomValidity('error');
    clickButton(captured.buttons[0]);
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
    captured.textComponents[0]?.setValue('updated-value');
    clickButton(captured.buttons[0]);
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
    getInputEl(captured.textComponents[0])?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
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
    getInputEl(captured.textComponents[0])?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
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
    getInputEl(captured.textComponents[0])?.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }));
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
    expect(isButtonDisabled(captured.buttons[2])).toBe(true);
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
    expect(isButtonDisabled(captured.buttons[2])).toBe(false);
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
    clickButton(captured.buttons[2]);
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
    clickButton(captured.buttons[2]);
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
    clickButton(captured.buttons[2]);
    await flushOnOpen();
    await vi.advanceTimersByTimeAsync(0);
    await flushOnOpen();
    expect(hoisted.embedComponent.unload).toHaveBeenCalled();
    expect(hoisted.mockTrashSafe).toHaveBeenCalled();
    await promise;
  });
});
