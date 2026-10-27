// @vitest-environment jsdom

import type { ConsoleDebugComponent } from '@mnaoumov/obsidian-lib/components/console-debug-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { App as AppOriginal } from 'obsidian';
import type { MockInstance } from 'vitest';

import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { noopAsync } from '@mnaoumov/typescript-lib/function';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  ButtonComponent,
  ExtraButtonComponent,
  Modal,
  TextComponent,
  ToggleComponent
} from 'obsidian';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { PluginSettings } from '../settings/plugin-settings.ts';
import type { TokenValidator } from '../tokens/token-validator.ts';
import type { OriginalAttachmentNameRecord } from './original-attachment-names-component.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';
import {
  formatOriginalAttachmentNamesAsCsv,
  isOriginalAttachmentNameRecordMatch,
  showOriginalAttachmentNamesModal,
  useCurrentNamesAsOriginals
} from './original-attachment-names-modal.ts';

/*
 * The components keep their handlers on the component instance rather than on the DOM node, so they are captured
 * as they are registered, which is what lets a test press a button the way a user does.
 */

interface ExtraButtonEntry {
  readonly handler: () => unknown;
  readonly tooltip: string;
}

let app: AppOriginal;
let buttonHandlers: Map<string, () => unknown>;
let extraButtonHandlers: ExtraButtonEntry[];
let extraButtonTooltips: Map<ExtraButtonComponent, string>;
let modalPromise: null | Promise<void>;
let openSpy: MockInstance<Modal['open']>;
let originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
let showNotice: ReturnType<typeof vi.fn<PluginNoticeComponent['showNotice']>>;
let textComponents: TextComponent[];
let textChangeHandlers: Map<TextComponent, (value: string) => void>;
let toggleHandlers: ((isSelected: boolean) => void)[];

const tokenValidator = strictProxy<TokenValidator>({
  validateFileName: ({ fileName }) => Promise.resolve(fileName.includes('|') ? 'File name contains invalid symbols' : '')
});

function clickButton(text: string): void {
  const handler = buttonHandlers.get(text);
  if (!handler) {
    throw new Error(`No button '${text}'.`);
  }
  handler();
}

function clickRowAction(rowIndex: number, tooltip: string): void {
  const handlers = extraButtonHandlers.filter((entry) => entry.tooltip === tooltip);
  const entry = handlers[rowIndex];
  if (!entry) {
    throw new Error(`No '${tooltip}' action on row ${String(rowIndex)}.`);
  }
  entry.handler();
}

async function flush(): Promise<void> {
  for (let index = 0; index < 10; index++) {
    await noopAsync();
  }
}

function getContentText(): string {
  return getModal()?.contentEl.textContent ?? '';
}

function getModal(): Modal | undefined {
  return castTo<Modal | undefined>(openSpy.mock.contexts.at(-1));
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

beforeEach(async () => {
  app = App.createConfigured__().asOriginalType__();
  buttonHandlers = new Map<string, () => unknown>();
  extraButtonHandlers = [];
  extraButtonTooltips = new Map<ExtraButtonComponent, string>();
  modalPromise = null;
  showNotice = vi.fn<PluginNoticeComponent['showNotice']>();
  textComponents = [];
  textChangeHandlers = new Map<TextComponent, (value: string) => void>();
  toggleHandlers = [];

  vi.spyOn(ButtonComponent.prototype, 'onClick').mockImplementation(function onClickMock(this: ButtonComponent, callback: (mouseEvent: MouseEvent) => unknown): ButtonComponent {
    buttonHandlers.set(this.buttonEl.textContent, () => callback(new MouseEvent('click')));
    return this;
  });
  vi.spyOn(ExtraButtonComponent.prototype, 'setTooltip').mockImplementation(function setTooltipMock(this: ExtraButtonComponent, tooltip: string): ExtraButtonComponent {
    extraButtonTooltips.set(this, tooltip);
    return this;
  });
  vi.spyOn(ExtraButtonComponent.prototype, 'onClick').mockImplementation(function onClickMock(this: ExtraButtonComponent, callback: () => unknown): ExtraButtonComponent {
    extraButtonHandlers.push({ handler: callback, tooltip: extraButtonTooltips.get(this) ?? '' });
    return this;
  });
  vi.spyOn(ToggleComponent.prototype, 'onChange').mockImplementation(function onChangeMock(this: ToggleComponent, callback: (isEnabled: boolean) => void): ToggleComponent {
    toggleHandlers.push(callback);
    return this;
  });
  const originalTextSetValue = TextComponent.prototype.setValue;
  vi.spyOn(TextComponent.prototype, 'setValue').mockImplementation(function setValueMock(this: TextComponent, value: string): TextComponent {
    if (!textComponents.includes(this)) {
      textComponents.push(this);
    }
    return originalTextSetValue.call(this, value);
  });
  vi.spyOn(TextComponent.prototype, 'onChange').mockImplementation(function onChangeMock(this: TextComponent, callback: (value: string) => void): TextComponent {
    textChangeHandlers.set(this, callback);
    return this;
  });
  openSpy = vi.spyOn(Modal.prototype, 'open');

  originalAttachmentNamesComponent = new OriginalAttachmentNamesComponent({
    app,
    consoleDebugComponent: strictProxy<ConsoleDebugComponent>({ consoleDebug: vi.fn() }),
    pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice: vi.fn() }),
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings: castTo<PluginSettings>({ shouldWarnWhenOriginalAttachmentNameIsUnknown: true }) }),
    storeFilePath: 'original-attachment-names.json'
  });
  originalAttachmentNamesComponent.load();

  await app.vault.createFolder('assets');
  await app.vault.createBinary('assets/note-img.png', new ArrayBuffer(1));
  await app.vault.createBinary('assets/screenshot.png', new ArrayBuffer(1));
  originalAttachmentNamesComponent.set('assets/note-img.png', 'img.png');
  originalAttachmentNamesComponent.set('assets/screenshot.png', 'Pasted image 20260101.png');
  originalAttachmentNamesComponent.set('assets/gone.png', 'gone.png');
});

afterEach(async () => {
  getModal()?.close();
  await modalPromise;
  originalAttachmentNamesComponent.unload();
  vi.restoreAllMocks();
});

function openModal(): void {
  modalPromise = showOriginalAttachmentNamesModal({
    app,
    originalAttachmentNamesComponent,
    pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice }),
    tokenValidator
  });
}

describe('showOriginalAttachmentNamesModal', () => {
  it('should list every record sorted by path, with the totals and a missing badge', () => {
    openModal();

    const text = getContentText();
    expect(text).toContain('3 record(s), 1 of them missing.');
    expect(text.indexOf('assets/gone.png')).toBeLessThan(text.indexOf('assets/note-img.png'));
    expect(text.indexOf('assets/note-img.png')).toBeLessThan(text.indexOf('assets/screenshot.png'));
    expect(getModal()?.contentEl.querySelectorAll('.original-attachment-names-missing')).toHaveLength(1);
  });

  it('should filter the rows by path or name', () => {
    openModal();
    const [onFilterChange] = textChangeHandlers.values();

    onFilterChange?.('pasted');

    expect(getContentText()).toContain('assets/screenshot.png');
    expect(getContentText()).not.toContain('assets/note-img.png');
  });

  it('should say so when no row matches the filter', () => {
    openModal();
    const [onFilterChange] = textChangeHandlers.values();

    onFilterChange?.('nothing like this');

    expect(getContentText()).toContain('No record matches the filter.');
  });

  it('should save an edited name when Enter is pressed, and ignore other keys', async () => {
    openModal();

    clickRowAction(1, 'Edit');
    const editor = textComponents.at(-1);
    editor?.setValue('typed.png');
    editor?.inputEl.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' }));
    await flush();
    expect(originalAttachmentNamesComponent.get('assets/note-img.png')).toBe('img.png');

    editor?.inputEl.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    await flush();
    expect(originalAttachmentNamesComponent.get('assets/note-img.png')).toBe('typed.png');
  });

  it('should leave the record alone when the edit is cancelled', () => {
    openModal();

    clickRowAction(1, 'Edit');
    textComponents.at(-1)?.setValue('discarded.png');
    clickButton('Cancel');

    expect(originalAttachmentNamesComponent.get('assets/note-img.png')).toBe('img.png');
    expect(getContentText()).toContain('img.png');
  });

  it('should drop a deselected row from the selection', () => {
    openModal();

    toggleHandlers[0]?.(true);
    toggleHandlers[0]?.(false);
    clickButton('Forget selected');

    expect(originalAttachmentNamesComponent.size).toBe(3);
  });

  it('should keep a selection across a re-render', () => {
    openModal();
    const [onFilterChange] = textChangeHandlers.values();

    toggleHandlers[1]?.(true);
    onFilterChange?.('assets');
    clickButton('Forget selected');

    expect(originalAttachmentNamesComponent.get('assets/note-img.png')).toBeUndefined();
    expect(originalAttachmentNamesComponent.size).toBe(2);
  });

  it('should drop a forgotten row from the selection', () => {
    openModal();

    toggleHandlers[0]?.(true);
    clickRowAction(0, 'Forget');
    originalAttachmentNamesComponent.set('assets/gone.png', 'recorded again.png');
    clickButton('Forget selected');

    expect(originalAttachmentNamesComponent.get('assets/gone.png')).toBe('recorded again.png');
  });

  it('should save an edited name that passes validation', async () => {
    openModal();

    // Row 1 is `assets/note-img.png`: the rows are sorted by path, and `assets/gone.png` comes first.
    clickRowAction(1, 'Edit');
    const editor = textComponents.at(-1);
    editor?.setValue('my photo.png');
    clickButton('Save');
    await flush();

    expect(originalAttachmentNamesComponent.get('assets/note-img.png')).toBe('my photo.png');
  });

  it('should reject an edited name that fails validation, and keep the record', async () => {
    openModal();

    clickRowAction(1, 'Edit');
    const editor = textComponents.at(-1);
    editor?.setValue('bad|name.png');
    clickButton('Save');
    await flush();

    expect(originalAttachmentNamesComponent.get('assets/note-img.png')).toBe('img.png');
    expect(getContentText()).toContain('File name contains invalid symbols');
  });

  it('should forget a single record', () => {
    openModal();

    clickRowAction(1, 'Forget');

    expect(originalAttachmentNamesComponent.get('assets/note-img.png')).toBeUndefined();
    expect(originalAttachmentNamesComponent.size).toBe(2);
    expect(getContentText()).toContain('2 record(s), 1 of them missing.');
  });

  it('should set a record to the file\'s current name', () => {
    openModal();

    clickRowAction(2, 'Use current name');

    expect(originalAttachmentNamesComponent.get('assets/screenshot.png')).toBe('screenshot.png');
  });

  it('should forget the selected rows at once', () => {
    openModal();

    toggleHandlers[0]?.(true);
    toggleHandlers[2]?.(true);
    clickButton('Forget selected');

    expect(originalAttachmentNamesComponent.getRecords().map((record) => record.path)).toStrictEqual(['assets/note-img.png']);
  });

  it('should use the current name for the selected rows at once, leaving a missing file alone', () => {
    openModal();

    toggleHandlers[0]?.(true);
    toggleHandlers[1]?.(true);
    toggleHandlers[2]?.(true);
    clickButton('Use current name for selected');

    expect(originalAttachmentNamesComponent.get('assets/gone.png')).toBe('gone.png');
    expect(originalAttachmentNamesComponent.get('assets/note-img.png')).toBe('note-img.png');
    expect(originalAttachmentNamesComponent.get('assets/screenshot.png')).toBe('screenshot.png');
  });

  it('should copy the shown records as CSV', async () => {
    const writeText = vi.fn<(text: string) => Promise<void>>().mockResolvedValue();
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    openModal();

    clickButton('Copy as CSV');
    await flush();

    expect(writeText).toHaveBeenCalledExactlyOnceWith('path,originalName\nassets/gone.png,gone.png\nassets/note-img.png,img.png\nassets/screenshot.png,Pasted image 20260101.png\n');
    expect(showNotice).toHaveBeenCalledExactlyOnceWith('Copied 3 record(s) as CSV.');
    vi.unstubAllGlobals();
  });

  it('should say so when nothing is remembered', () => {
    originalAttachmentNamesComponent.forgetAll();
    openModal();

    expect(getContentText()).toContain('No original attachment names are remembered yet.');
  });
});

describe('original attachment name helpers', () => {
  const record: OriginalAttachmentNameRecord = { isMissing: false, originalFileName: 'Pasted image.png', path: 'assets/Shot.png' };

  it('should match a filter by path or name, ignoring case', () => {
    expect(isOriginalAttachmentNameRecordMatch(record, '')).toBe(true);
    expect(isOriginalAttachmentNameRecordMatch(record, 'shot')).toBe(true);
    expect(isOriginalAttachmentNameRecordMatch(record, 'PASTED')).toBe(true);
    expect(isOriginalAttachmentNameRecordMatch(record, 'other')).toBe(false);
  });

  it('should quote a CSV field that holds a comma, a quote or a line break', () => {
    expect(formatOriginalAttachmentNamesAsCsv([
      { isMissing: false, originalFileName: 'a "quoted", name.png', path: 'plain.png' }
    ])).toBe('path,originalName\nplain.png,"a ""quoted"", name.png"\n');
  });

  it('should count only the records whose file exists when using current names', () => {
    expect(useCurrentNamesAsOriginals(originalAttachmentNamesComponent, app, ['assets/note-img.png', 'assets/gone.png'])).toBe(1);
  });
});
