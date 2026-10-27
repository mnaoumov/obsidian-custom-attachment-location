import type { ConsoleDebugComponent } from '@mnaoumov/obsidian-lib/components/console-debug-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';

import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { alert } from '@mnaoumov/obsidian-lib/modals/alert';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { ButtonComponent } from 'obsidian';
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
import { ActionContext } from '../tokens/token-evaluator-context.ts';
import { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

vi.mock('@mnaoumov/obsidian-lib/modals/alert', () => ({
  alert: vi.fn()
}));

const mockAlert = vi.mocked(alert);

const STORE_FOLDER_PATH = 'plugin-folder';
const STORE_FILE_PATH = `${STORE_FOLDER_PATH}/original-attachment-names.json`;
// Mirrors the debounce delays in the component under test.
const SAVE_DEBOUNCE_IN_MILLISECONDS = 1000;
const WARNING_DEBOUNCE_IN_MILLISECONDS = 1000;
const EXPECTED_ARRIVAL_TIMEOUT_IN_MILLISECONDS = 60_000;

describe('OriginalAttachmentNamesComponent', () => {
  let app: App;
  let component: OriginalAttachmentNamesComponent;
  let consoleDebug: ReturnType<typeof vi.fn<ConsoleDebugComponent['consoleDebug']>>;
  let isWarningEnabled: boolean;
  let showNotice: ReturnType<typeof vi.fn<PluginNoticeComponent['showNotice']>>;

  function getApp(): ReturnType<App['asOriginalType__']> {
    return app.asOriginalType__();
  }

  async function createComponent(): Promise<OriginalAttachmentNamesComponent> {
    const created = new OriginalAttachmentNamesComponent({
      app: getApp(),
      consoleDebugComponent: strictProxy<ConsoleDebugComponent>({ consoleDebug }),
      pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice }),
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
        get settings(): PluginSettings {
          return castTo<PluginSettings>({ shouldWarnWhenOriginalAttachmentNameIsUnknown: isWarningEnabled });
        }
      }),
      storeFilePath: STORE_FILE_PATH
    });
    await created.loadFromDisk();
    created.load();
    return created;
  }

  async function readStoreFile(): Promise<unknown> {
    return JSON.parse(await getApp().vault.adapter.read(STORE_FILE_PATH));
  }

  beforeAll(async () => {
    await initI18N(translationsMap);
  });

  beforeEach(async () => {
    vi.useFakeTimers();
    app = App.createConfigured__();
    consoleDebug = vi.fn<ConsoleDebugComponent['consoleDebug']>();
    showNotice = vi.fn<PluginNoticeComponent['showNotice']>();
    isWarningEnabled = true;
    await getApp().vault.adapter.mkdir(STORE_FOLDER_PATH);
    await getApp().vault.createFolder('assets');
    component = await createComponent();
  });

  afterEach(() => {
    component.unload();
    vi.useRealTimers();
  });

  it('should retain a source path across reloads and renames and remove it when forgotten', async () => {
    const file = await getApp().vault.createBinary('assets/source.png', new ArrayBuffer(1));
    component.setOriginalPath(file.path, String.raw`C:\Pictures\original.png`);
    expect(component.get(file.path)).toBeUndefined();
    await vi.advanceTimersByTimeAsync(SAVE_DEBOUNCE_IN_MILLISECONDS);
    const reloaded = await createComponent();
    expect(reloaded.getOriginalPath(file.path)).toBe(String.raw`C:\Pictures\original.png`);
    await getApp().vault.rename(file, 'assets/renamed.png');
    expect(reloaded.getOriginalPath('assets/source.png')).toBeUndefined();
    expect(reloaded.getOriginalPath(file.path)).toBe(String.raw`C:\Pictures\original.png`);
    reloaded.forget([file.path]);
    expect(reloaded.getOriginalPath(file.path)).toBeUndefined();
    reloaded.unload();
  });

  it('should leave the original path intact when the user changes the original name', async () => {
    component.set('assets/a.pdf', 'old.pdf');
    component.setOriginalPath('assets/a.pdf', '/Downloads/old.pdf');
    component.set('assets/a.pdf', 'corrected.pdf');
    await vi.runAllTimersAsync();
    const write = vi.spyOn(getApp().vault.adapter, 'write');
    component.setOriginalPath('assets/a.pdf', '/Downloads/old.pdf');
    component.setOriginalPath('assets/a.pdf', '');
    await vi.runAllTimersAsync();
    expect(component.getOriginalPath('assets/a.pdf')).toBe('/Downloads/old.pdf');
    expect(component.get('assets/a.pdf')).toBe('corrected.pdf');
    expect(write).not.toHaveBeenCalled();
    expect(component.forgetAll()).toBe(1);
    expect(component.getOriginalPath('assets/a.pdf')).toBeUndefined();
  });

  it.each([null, [], 4, { 'assets/a.pdf': '/Downloads/a.pdf', 'empty': '', 'invalid': 4 }])('should load only nonempty source paths from optional metadata: %j', async (originalPaths) => {
    await getApp().vault.adapter.write(STORE_FILE_PATH, JSON.stringify({ names: {}, originalPaths, version: 1 }));
    const reloaded = await createComponent();
    expect(reloaded.getOriginalPath('invalid')).toBeUndefined();
    expect(reloaded.getOriginalPath('empty')).toBeUndefined();
    expect(reloaded.getOriginalPath('assets/a.pdf')).toBe(originalPaths !== null && !Array.isArray(originalPaths) && typeof originalPaths === 'object' ? '/Downloads/a.pdf' : undefined);
    reloaded.unload();
  });

  it('should move and delete source-path metadata with its folder even without an original name', async () => {
    const folder = await getApp().vault.createFolder('assets/source');
    component.setOriginalPath('assets/source/a.pdf', '/Downloads/a.pdf');
    await getApp().vault.rename(folder, 'assets/moved');
    expect(component.getOriginalPath('assets/source/a.pdf')).toBeUndefined();
    expect(component.getOriginalPath('assets/moved/a.pdf')).toBe('/Downloads/a.pdf');
    await getApp().fileManager.trashFile(folder);
    expect(component.getOriginalPath('assets/moved/a.pdf')).toBeUndefined();
  });

  describe('arrival', () => {
    it('should record the arrival name once the expected file is created', async () => {
      component.expectArrival('assets/Note-img.png', 'img.png');

      await getApp().vault.createBinary('assets/Note-img.png', new ArrayBuffer(1));

      expect(component.get('assets/Note-img.png')).toBe('img.png');
    });

    it('should not record a path that was handed out but never created', () => {
      component.expectArrival('assets/probe.png', 'probe.png');

      expect(component.get('assets/probe.png')).toBeUndefined();
      expect(component.size).toBe(0);
    });

    it('should not record a file created after the expectation expired', async () => {
      component.expectArrival('assets/late.png', 'late.png');
      vi.advanceTimersByTime(EXPECTED_ARRIVAL_TIMEOUT_IN_MILLISECONDS + 1);

      await getApp().vault.createBinary('assets/late.png', new ArrayBuffer(1));

      expect(component.get('assets/late.png')).toBeUndefined();
    });

    it('should ignore a file nobody expected', async () => {
      await getApp().vault.createBinary('assets/synced.png', new ArrayBuffer(1));

      expect(component.get('assets/synced.png')).toBeUndefined();
    });
  });

  describe('vault events', () => {
    it('should follow a rename inside Obsidian', async () => {
      const file = await getApp().vault.createBinary('assets/img.png', new ArrayBuffer(1));
      component.set(file.path, 'img.png');

      await getApp().vault.rename(file, 'assets/renamed.png');

      expect(component.get('assets/img.png')).toBeUndefined();
      expect(component.get('assets/renamed.png')).toBe('img.png');
    });

    it('should follow a folder rename for every record under it', async () => {
      await getApp().vault.createFolder('assets/sub');
      await getApp().vault.createBinary('assets/sub/a.png', new ArrayBuffer(1));
      await getApp().vault.createBinary('assets/sub/b.png', new ArrayBuffer(1));
      component.set('assets/sub/a.png', 'first.png');
      component.set('assets/sub/b.png', 'second.png');
      component.set('assets/subway.png', 'unrelated.png');

      const folder = getApp().vault.getFolderByPath('assets/sub');
      if (!folder) {
        throw new Error('The folder was not created.');
      }
      await getApp().vault.rename(folder, 'assets/moved');

      expect(component.get('assets/moved/a.png')).toBe('first.png');
      expect(component.get('assets/moved/b.png')).toBe('second.png');
      expect(component.get('assets/sub/a.png')).toBeUndefined();
      expect(component.get('assets/subway.png')).toBe('unrelated.png');
    });

    it('should change nothing when a file with no record is renamed', async () => {
      const file = await getApp().vault.createBinary('assets/img.png', new ArrayBuffer(1));
      component.set('assets/other.png', 'other.png');

      await getApp().vault.rename(file, 'assets/renamed.png');

      expect(component.getRecords().map((record) => record.path)).toStrictEqual(['assets/other.png']);
    });

    it('should prune the record when the file is deleted', async () => {
      const file = await getApp().vault.createBinary('assets/img.png', new ArrayBuffer(1));
      component.set(file.path, 'img.png');

      await getApp().fileManager.trashFile(file);

      expect(component.get('assets/img.png')).toBeUndefined();
      expect(component.size).toBe(0);
    });

    it('should prune every record under a deleted folder', async () => {
      await getApp().vault.createFolder('assets/sub');
      await getApp().vault.createBinary('assets/sub/a.png', new ArrayBuffer(1));
      component.set('assets/sub/a.png', 'first.png');
      component.set('assets/kept.png', 'kept.png');

      const folder = getApp().vault.getFolderByPath('assets/sub');
      if (!folder) {
        throw new Error('The folder was not created.');
      }
      await getApp().fileManager.trashFile(folder);

      expect(component.get('assets/sub/a.png')).toBeUndefined();
      expect(component.get('assets/kept.png')).toBe('kept.png');
    });
  });

  describe('persistence', () => {
    it('should write a compact file of its own and read it back on the next load', async () => {
      component.set('assets/img.png', 'Pasted image 1.png');
      vi.advanceTimersByTime(SAVE_DEBOUNCE_IN_MILLISECONDS);
      await vi.runAllTimersAsync();

      const raw = await getApp().vault.adapter.read(STORE_FILE_PATH);
      expect(raw).not.toContain('\n');
      expect(await readStoreFile()).toStrictEqual({ names: { 'assets/img.png': 'Pasted image 1.png' }, version: 1 });

      const reloaded = await createComponent();
      expect(reloaded.get('assets/img.png')).toBe('Pasted image 1.png');
      reloaded.unload();
    });

    it('should save a pending change when it unloads', async () => {
      component.set('assets/img.png', 'img.png');
      component.unload();
      await vi.runAllTimersAsync();

      expect(await readStoreFile()).toStrictEqual({ names: { 'assets/img.png': 'img.png' }, version: 1 });
    });

    it('should load nothing from a damaged file', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      await getApp().vault.adapter.write(STORE_FILE_PATH, '{ not json');

      const reloaded = await createComponent();

      expect(reloaded.size).toBe(0);
      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      reloaded.unload();
    });

    it('should load nothing from a file of another shape', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      await getApp().vault.adapter.write(STORE_FILE_PATH, JSON.stringify(['assets/img.png']));

      const reloaded = await createComponent();

      expect(reloaded.size).toBe(0);
      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      reloaded.unload();
    });

    it('should load nothing from a file holding no object', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
      await getApp().vault.adapter.write(STORE_FILE_PATH, 'null');

      const reloaded = await createComponent();

      expect(reloaded.size).toBe(0);
      expect(consoleErrorSpy).toHaveBeenCalledOnce();
      reloaded.unload();
    });

    it('should not save again when a record is set to the name it already has', async () => {
      component.set('assets/img.png', 'img.png');
      await vi.runAllTimersAsync();
      const writeSpy = vi.spyOn(getApp().vault.adapter, 'write');

      component.set('assets/img.png', 'img.png');
      await vi.runAllTimersAsync();

      expect(writeSpy).not.toHaveBeenCalled();
    });

    it('should skip an entry whose name is not a string', async () => {
      await getApp().vault.adapter.write(STORE_FILE_PATH, JSON.stringify({ names: { 'a.png': 'a.png', 'b.png': 1 }, version: 1 }));

      const reloaded = await createComponent();

      expect(reloaded.getRecords().map((record) => record.path)).toStrictEqual(['a.png']);
      reloaded.unload();
    });
  });

  describe('reportUnknown', () => {
    it('should remember the current name and warn ONCE for every unknown name of one operation', async () => {
      await getApp().vault.createBinary('assets/a.png', new ArrayBuffer(1));
      await getApp().vault.createBinary('assets/b.png', new ArrayBuffer(1));

      component.reportUnknown({ actionContext: ActionContext.CollectAttachments, currentFileName: 'a.png', path: 'assets/a.png' });
      component.reportUnknown({ actionContext: ActionContext.CollectAttachments, currentFileName: 'b.png', path: 'assets/b.png' });
      component.reportUnknown({ actionContext: ActionContext.CollectAttachments, currentFileName: 'a.png', path: 'assets/a.png' });
      expect(showNotice).not.toHaveBeenCalled();

      vi.advanceTimersByTime(WARNING_DEBOUNCE_IN_MILLISECONDS);

      expect(showNotice).toHaveBeenCalledOnce();
      const message = showNotice.mock.calls[0]?.[0];
      expect(message).toBeInstanceOf(DocumentFragment);
      expect((message as DocumentFragment).textContent).toContain('the original name of 2 attachment(s) is unknown');
      expect(component.get('assets/a.png')).toBe('a.png');
      expect(component.get('assets/b.png')).toBe('b.png');
      expect(consoleDebug).toHaveBeenCalledTimes(3);
    });

    it('should list the paths behind Details', () => {
      let onDetailsClick: (() => unknown) | null = null;
      vi.spyOn(ButtonComponent.prototype, 'onClick').mockImplementation(function onClickMock(this: ButtonComponent, callback: (mouseEvent: MouseEvent) => unknown): ButtonComponent {
        onDetailsClick = (): unknown => callback(new MouseEvent('click'));
        return this;
      });
      component.reportUnknown({ actionContext: ActionContext.CollectAttachments, currentFileName: 'b.png', path: 'assets/b.png' });
      component.reportUnknown({ actionContext: ActionContext.CollectAttachments, currentFileName: 'a.png', path: 'assets/a.png' });
      vi.advanceTimersByTime(WARNING_DEBOUNCE_IN_MILLISECONDS);
      castTo<() => unknown>(onDetailsClick)();

      expect(mockAlert).toHaveBeenCalledOnce();
      const alertMessage = mockAlert.mock.calls[0]?.[0].message as DocumentFragment;
      expect([...alertMessage.querySelectorAll('li')].map((listItem) => listItem.textContent)).toStrictEqual(['assets/a.png', 'assets/b.png']);
    });

    it('should start a new warning for the next operation', () => {
      component.reportUnknown({ actionContext: ActionContext.CollectAttachments, currentFileName: 'a.png', path: 'assets/a.png' });
      vi.advanceTimersByTime(WARNING_DEBOUNCE_IN_MILLISECONDS);
      component.reportUnknown({ actionContext: ActionContext.RenameNote, currentFileName: 'b.png', path: 'assets/b.png' });
      vi.advanceTimersByTime(WARNING_DEBOUNCE_IN_MILLISECONDS);

      expect(showNotice).toHaveBeenCalledTimes(2);
      expect((showNotice.mock.calls[1]?.[0] as DocumentFragment).textContent).toContain('the original name of 1 attachment(s) is unknown');
    });

    it('should remember the name but stay quiet when the warning is turned off', () => {
      isWarningEnabled = false;

      component.reportUnknown({ actionContext: ActionContext.CollectAttachments, currentFileName: 'a.png', path: 'assets/a.png' });
      vi.advanceTimersByTime(WARNING_DEBOUNCE_IN_MILLISECONDS);

      expect(showNotice).not.toHaveBeenCalled();
      expect(component.get('assets/a.png')).toBe('a.png');
      expect(consoleDebug).toHaveBeenCalledOnce();
    });

    it('should neither remember nor warn for a read through the published API', () => {
      component.reportUnknown({ actionContext: ActionContext.ReadApi, currentFileName: 'a.png', path: 'assets/a.png' });
      vi.advanceTimersByTime(WARNING_DEBOUNCE_IN_MILLISECONDS);

      expect(showNotice).not.toHaveBeenCalled();
      expect(component.get('assets/a.png')).toBeUndefined();
      expect(consoleDebug).toHaveBeenCalledOnce();
    });

    it('should keep a record that already exists', () => {
      component.set('assets/a.png', 'arrived.png');

      component.reportUnknown({ actionContext: ActionContext.CollectAttachments, currentFileName: 'a.png', path: 'assets/a.png' });

      expect(component.get('assets/a.png')).toBe('arrived.png');
    });
  });

  describe('forget and prune', () => {
    it('should prune the records whose file no longer exists and keep the live ones', async () => {
      await getApp().vault.createBinary('assets/live.png', new ArrayBuffer(1));
      component.set('assets/live.png', 'live.png');
      component.set('assets/gone.png', 'gone.png');

      const removed = component.prune();

      expect(removed).toStrictEqual([{ isMissing: true, originalFileName: 'gone.png', path: 'assets/gone.png' }]);
      expect(component.get('assets/live.png')).toBe('live.png');
      expect(component.get('assets/gone.png')).toBeUndefined();
    });

    it('should forget every record', () => {
      component.set('assets/a.png', 'a.png');
      component.set('assets/b.png', 'b.png');

      expect(component.forgetAll()).toBe(2);
      expect(component.size).toBe(0);
      expect(component.forgetAll()).toBe(0);
    });

    it('should forget only the named records', () => {
      component.set('assets/a.png', 'a.png');
      component.set('assets/b.png', 'b.png');

      expect(component.forget(['assets/a.png', 'assets/unknown.png'])).toBe(1);
      expect(component.get('assets/a.png')).toBeUndefined();
      expect(component.get('assets/b.png')).toBe('b.png');
    });

    it('should list the records sorted by path, flagging the missing ones', async () => {
      await getApp().vault.createBinary('assets/b.png', new ArrayBuffer(1));
      component.set('assets/b.png', 'second.png');
      component.set('assets/a.png', 'first.png');

      expect(component.getRecords()).toStrictEqual([
        { isMissing: true, originalFileName: 'first.png', path: 'assets/a.png' },
        { isMissing: false, originalFileName: 'second.png', path: 'assets/b.png' }
      ]);
    });
  });
});
