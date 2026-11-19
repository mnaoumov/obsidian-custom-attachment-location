// @vitest-environment jsdom

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
  Modal
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

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { showOriginalFileNameModal } from './original-file-name-modal.ts';

let app: AppOriginal;
let buttonHandlers: Map<string, () => unknown>;
let copyHandler: (() => unknown) | null;
let openSpy: MockInstance<Modal['open']>;
let showNotice: MockInstance<PluginNoticeComponent['showNotice']> & PluginNoticeComponent['showNotice'];

async function flush(): Promise<void> {
  for (let index = 0; index < 10; index++) {
    await noopAsync();
  }
}

function getModal(): Modal {
  const modal = castTo<Modal | undefined>(openSpy.mock.contexts.at(-1));
  if (!modal) {
    throw new Error('No modal was opened.');
  }
  return modal;
}

function open(): Promise<void> {
  return showOriginalFileNameModal({
    app,
    attachmentPath: 'assets/renamed.pdf',
    originalFileName: 'alpha-bravo-charlie.pdf',
    pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice })
  });
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

beforeEach(() => {
  app = App.createConfigured__().asOriginalType__();
  buttonHandlers = new Map<string, () => unknown>();
  copyHandler = null;
  showNotice = vi.fn<PluginNoticeComponent['showNotice']>();
  vi.spyOn(ButtonComponent.prototype, 'onClick').mockImplementation(function onClickMock(this: ButtonComponent, callback: (mouseEvent: MouseEvent) => unknown): ButtonComponent {
    buttonHandlers.set(this.buttonEl.textContent, () => callback(new MouseEvent('click')));
    return this;
  });
  vi.spyOn(ExtraButtonComponent.prototype, 'onClick').mockImplementation(function onClickMock(this: ExtraButtonComponent, callback: () => unknown): ExtraButtonComponent {
    copyHandler = callback;
    return this;
  });
  openSpy = vi.spyOn(Modal.prototype, 'open');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('showOriginalFileNameModal', () => {
  it('should show the name in a read-only box, naming the attachment', async () => {
    const promise = open();
    const modal = getModal();
    expect(modal.titleEl.textContent).toBe('Original file name');
    expect(modal.contentEl.textContent).toContain('assets/renamed.pdf');
    const input = modal.contentEl.querySelector('input');
    expect(input?.value).toBe('alpha-bravo-charlie.pdf');
    expect(input?.readOnly).toBe(true);
    buttonHandlers.get('Close')?.();
    await promise;
  });

  it('should copy the name and say so when the copy button is pressed', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    const promise = open();
    copyHandler?.();
    await flush();
    expect(writeText.mock.calls).toStrictEqual([['alpha-bravo-charlie.pdf']]);
    expect(showNotice.mock.calls).toStrictEqual([['Copied the original file name: alpha-bravo-charlie.pdf']]);
    getModal().close();
    await promise;
  });

  it('should tell the user to copy by hand when the clipboard refuses', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'));
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    vi.spyOn(console, 'error').mockImplementation(vi.fn());
    const promise = open();
    copyHandler?.();
    await flush();
    expect(showNotice.mock.calls).toStrictEqual([[
      'Could not copy the original file name to the clipboard. Select it in the box and copy it by hand.'
    ]]);
    getModal().close();
    await promise;
  });

  it('should select the whole name when the box is focused', async () => {
    const promise = open();
    const input = getModal().contentEl.querySelector('input');
    if (!input) {
      throw new Error('No input.');
    }
    const selectSpy = vi.spyOn(input, 'select');
    input.dispatchEvent(new FocusEvent('focus'));
    expect(selectSpy).toHaveBeenCalled();
    getModal().close();
    await promise;
  });
});
