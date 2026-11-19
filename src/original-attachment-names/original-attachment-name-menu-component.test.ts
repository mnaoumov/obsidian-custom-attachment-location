import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type {
  Menu,
  MenuItem
} from 'obsidian';

import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { TFile } from 'obsidian';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { OriginalAttachmentNameMenuComponent } from './original-attachment-name-menu-component.ts';
import { showOriginalFileNameModal } from './original-file-name-modal.ts';

vi.mock('./original-file-name-modal.ts', () => ({
  showOriginalFileNameModal: vi.fn().mockResolvedValue(undefined)
}));

const showOriginalFileNameModalMock = vi.mocked(showOriginalFileNameModal);

interface CapturedItem {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  click: Parameters<MenuItem['onClick']>[0];
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  isDisabled: boolean;
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  title: string;
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

afterEach(() => {
  showOriginalFileNameModalMock.mockClear();
});

describe('Original attachment file name menu', () => {
  it.each([undefined, 'arrival.pdf', ''])('should enable the action and show the stored original file name: %j', async (name) => {
    const app = App.createConfigured__().asOriginalType__();
    const file = await app.vault.createBinary('renamed.pdf', new ArrayBuffer(1));
    const pluginNoticeComponent = strictProxy<PluginNoticeComponent>({});
    const component = new OriginalAttachmentNameMenuComponent({
      app,
      originalAttachmentNamesComponent: strictProxy<OriginalAttachmentNamesComponent>({ get: () => name ?? null }),
      pluginNoticeComponent,
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ isNoteEx: (candidate) => candidate instanceof TFile && candidate.extension === 'md' })
    });
    const items: CapturedItem[] = [];
    const menu: Menu = strictProxy<Menu>({
      addItem: (build) => {
        const captured: CapturedItem = { click: vi.fn(), isDisabled: false, title: '' };
        const item: MenuItem = strictProxy<MenuItem>({
          onClick: (click) => {
            captured.click = click;
            return item;
          },
          setDisabled: (isDisabled) => {
            captured.isDisabled = isDisabled;
            return item;
          },
          setIcon: () => item,
          setSection: () => item,
          setTitle: (title) => {
            captured.title = typeof title === 'string' ? title : title.textContent;
            return item;
          }
        });
        build(item);
        items.push(captured);
        return menu;
      }
    });
    component.load();
    try {
      app.workspace.trigger('file-menu', menu, file, 'file-explorer');
      expect(items.map((item) => [item.title, item.isDisabled])).toStrictEqual([
        ['Show original file name', !name]
      ]);
      for (const item of items) {
        item.click(new MouseEvent('click'));
      }
      await vi.waitFor(() => {
        expect(showOriginalFileNameModalMock.mock.calls).toStrictEqual(name ? [[{ app, attachmentPath: 'renamed.pdf', originalFileName: name, pluginNoticeComponent }]] : []);
      });
      const note = await app.vault.create('note.md', '');
      const folder = await app.vault.createFolder('folder');
      app.workspace.trigger('file-menu', menu, note, 'file-explorer');
      app.workspace.trigger('file-menu', menu, folder, 'file-explorer');
      expect(items).toHaveLength(1);
    } finally {
      component.unload();
    }
    app.workspace.trigger('file-menu', menu, file, 'link-context-menu');
    expect(items).toHaveLength(1);
  });
});
