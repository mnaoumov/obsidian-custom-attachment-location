// @vitest-environment jsdom

import type { ConsoleDebugComponent } from '@mnaoumov/obsidian-lib/components/console-debug-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { App as AppOriginal } from 'obsidian';
import type { MockInstance } from 'vitest';

import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { confirm } from '@mnaoumov/obsidian-lib/modals/confirm';
import { noopAsync } from '@mnaoumov/typescript-lib/function';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  ButtonComponent,
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

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { PluginSettings } from '../settings/plugin-settings.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';
import {
  PruneOriginalAttachmentNamesChoice,
  showPruneOriginalAttachmentNamesModal
} from './prune-original-attachment-names-modal.ts';

vi.mock('@mnaoumov/obsidian-lib/modals/confirm', () => ({
  confirm: vi.fn()
}));

const mockConfirm = vi.mocked(confirm);

let app: AppOriginal;
let buttonHandlers: Map<string, () => unknown>;
let openSpy: MockInstance<Modal['open']>;
let originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;

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
  mockConfirm.mockReset();
  app = App.createConfigured__().asOriginalType__();
  buttonHandlers = new Map<string, () => unknown>();
  vi.spyOn(ButtonComponent.prototype, 'onClick').mockImplementation(function onClickMock(this: ButtonComponent, callback: (mouseEvent: MouseEvent) => unknown): ButtonComponent {
    buttonHandlers.set(this.buttonEl.textContent, () => callback(new MouseEvent('click')));
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
  await app.vault.createBinary('live.png', new ArrayBuffer(1));
  originalAttachmentNamesComponent.set('live.png', 'arrived.png');
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('showPruneOriginalAttachmentNamesModal', () => {
  it('should list the stale records and answer Prune when the user prunes', async () => {
    originalAttachmentNamesComponent.set('gone.png', 'gone.png');
    const choicePromise = showPruneOriginalAttachmentNamesModal({ app, originalAttachmentNamesComponent });

    expect(getContentText()).toContain('1 remembered name(s) belong to a path that no longer exists');
    expect(getContentText()).toContain('gone.png → gone.png');
    expect(getContentText()).not.toContain('live.png');
    buttonHandlers.get('Prune')?.();

    expect(await choicePromise).toBe(PruneOriginalAttachmentNamesChoice.Prune);
    // The dialog only answers; the command removes the records.
    expect(originalAttachmentNamesComponent.size).toBe(2);
  });

  it('should offer no Prune when nothing is stale, but still offer Forget all', async () => {
    const choicePromise = showPruneOriginalAttachmentNamesModal({ app, originalAttachmentNamesComponent });

    expect(getContentText()).toContain('nothing to prune');
    expect(buttonHandlers.has('Prune')).toBe(false);
    expect(buttonHandlers.has('Forget all')).toBe(true);
    buttonHandlers.get('Cancel')?.();
    expect(await choicePromise).toBe(PruneOriginalAttachmentNamesChoice.Cancel);
  });

  it('should answer Forget all only after the confirmation', async () => {
    mockConfirm.mockResolvedValue(true);
    const choicePromise = showPruneOriginalAttachmentNamesModal({ app, originalAttachmentNamesComponent });

    buttonHandlers.get('Forget all')?.();

    expect(await choicePromise).toBe(PruneOriginalAttachmentNamesChoice.ForgetAll);
    expect(mockConfirm).toHaveBeenCalledOnce();
    const message = mockConfirm.mock.calls[0]?.[0].message;
    expect(message instanceof DocumentFragment ? message.textContent : message).toContain('{{originalAttachmentFileName}}');
  });

  it('should stay open when the confirmation is declined', async () => {
    mockConfirm.mockResolvedValue(false);
    let isSettled = false;
    const choicePromise = showPruneOriginalAttachmentNamesModal({ app, originalAttachmentNamesComponent }).then((choice) => {
      isSettled = true;
      return choice;
    });

    buttonHandlers.get('Forget all')?.();
    await flush();

    expect(isSettled).toBe(false);
    buttonHandlers.get('Cancel')?.();
    expect(await choicePromise).toBe(PruneOriginalAttachmentNamesChoice.Cancel);
  });
});
