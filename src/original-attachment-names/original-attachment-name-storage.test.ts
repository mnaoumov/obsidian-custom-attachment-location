import type { ConsoleDebugComponent } from '@mnaoumov/obsidian-lib/components/console-debug-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';

import { LocalDataStore } from '@mnaoumov/obsidian-lib/data-stores/local-data-store';
import { SharedDataStore } from '@mnaoumov/obsidian-lib/data-stores/shared-data-store';
import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { waitForAllAsyncOperations } from '@mnaoumov/typescript-test-toolkit/async-operation-tracking';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { IDBFactory } from 'fake-indexeddb';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  beforeEach,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { PluginSettings } from '../settings/plugin-settings.ts';
import { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';
import {
  DEFAULT_PLUGIN_DATA_FOLDER,
  LEGACY_PLUGIN_DATA_FOLDER,
  validatePluginDataFolder
} from './plugin-data-folder.ts';

const ANCHOR = DEFAULT_PLUGIN_DATA_FOLDER;
const ROOT = `${ANCHOR}/obsidian-custom-attachment-location/original-attachment-names-v1`;
const LEGACY_ROOT = `${LEGACY_PLUGIN_DATA_FOLDER}/obsidian-custom-attachment-location/original-attachment-names-v1`;
const TARGET = '99-Meta/.names';
const TARGET_ROOT = `${TARGET}/obsidian-custom-attachment-location/original-attachment-names-v1`;
let app: ReturnType<App['asOriginalType__']>;
let settings: PluginSettings;
let components: OriginalAttachmentNamesComponent[];

async function createComponent(): Promise<OriginalAttachmentNamesComponent> {
  const component = new OriginalAttachmentNamesComponent({
    app,
    consoleDebugComponent: strictProxy<ConsoleDebugComponent>({ consoleDebug: vi.fn() }),
    pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice: vi.fn() }),
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings }),
    storeFilePath: 'plugin-folder/original-attachment-names.json'
  });
  await component.loadFromDisk();
  component.load();
  components.push(component);
  return component;
}

beforeEach(() => {
  app = App.createConfigured__().asOriginalType__();
  settings = new PluginSettings();
  components = [];
});

afterEach(async () => {
  vi.restoreAllMocks();
  for (const component of components) {
    await component.flush();
    component.unload();
    await waitForAllAsyncOperations();
  }
});

beforeAll(async () => {
  await initI18N(translationsMap);
});

it('keeps new original-name history locally across reload without creating transport files', async () => {
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.flush();
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(await component.getExistingStoreFolders()).toEqual([]);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(reloaded.isSyncEnabled).toBe(false);
});

it('retains legacy Markdown until setup explicitly approves JSON, preserving all original names', async () => {
  const local = await LocalDataStore.open({ pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1', vaultId: app.appId });
  const shared = await SharedDataStore.open({ adapter: app.vault.adapter, kind: 'last-write-wins', local, pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1' });
  await shared.set('legacy-alpha', { fileName: 'arrival.pdf', kind: 'arrival', path: 'assets/alpha.pdf', time: 1 });
  local.close();
  const component = await createComponent();
  expect(component.isSyncEnabled).toBe(true);
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  // An earlier version's replica keeps the folder it already writes to.
  expect(component.transportRoots).toContain(LEGACY_ROOT);
  const oldDevices = await app.vault.adapter.list(`${LEGACY_ROOT}/devices`);
  const oldDocuments = await app.vault.adapter.list(String(oldDevices.folders[0]));
  expect(oldDocuments.files.every((path) => path.endsWith('.md'))).toBe(true);
  await expect(component.relocate('99-Meta/Names')).rejects.toThrow('Complete synchronization setup');
  await component.setSyncEnabled(true);
  expect(await app.vault.adapter.exists(ROOT)).toBe(false);
  const devices = await app.vault.adapter.list(`${LEGACY_ROOT}/devices`);
  const documents = await app.vault.adapter.list(String(devices.folders[0]));
  expect(documents.files.some((path) => path.endsWith('.json'))).toBe(true);
});

it('keeps disabled device consent across reload even when sync settings and files arrive', async () => {
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.setSyncEnabled(true);
  await component.setSyncEnabled(false);
  settings.pluginDataFolder = 'Different destination';
  const adapterCalls = vi.spyOn(app.vault.adapter, 'write');
  const reloaded = await createComponent();
  reloaded.set('assets/bravo.pdf', 'bravo.pdf');
  await reloaded.flush();
  expect(adapterCalls).not.toHaveBeenCalled();
  expect(reloaded.isSyncEnabled).toBe(false);
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(await app.vault.adapter.exists('Different destination')).toBe(false);
});

it('requires new-device consent before merging the shared history', async () => {
  const first = await createComponent();
  first.set('assets/alpha.pdf', 'arrival.pdf');
  await first.setSyncEnabled(true);
  vi.stubGlobal('indexedDB', new IDBFactory());
  const second = await createComponent();
  expect(second.isSyncEnabled).toBe(false);
  // A folder arriving through sync is not permission to start transport on a new device.
  expect(second.get('assets/alpha.pdf')).toBeUndefined();
  await second.setSyncEnabled(true);
  expect(second.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('relocates from a fixed anchor, retains history and remembers hidden roots while disabled', async () => {
  settings.shouldAllowHiddenPluginDataFolder = true;
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.setSyncEnabled(true);
  await component.relocate(TARGET);
  await component.relocate(TARGET);
  expect(component.transportRoots).toContain(TARGET_ROOT);
  expect(await app.vault.adapter.exists(ROOT)).toBe(true);
  await component.setSyncEnabled(false);
  const reloaded = await createComponent();
  expect(reloaded.transportRoots).toContain(TARGET_ROOT);
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(reloaded.isSyncEnabled).toBe(false);
  await reloaded.setSyncEnabled(true);
  expect(reloaded.transportRoots).toEqual(component.transportRoots);
});

it('refuses relocation before consent and rejects unsafe destinations without moving history', async () => {
  const component = await createComponent();
  await expect(component.relocate('99-Meta/Names')).rejects.toThrow('Enable synchronization');
  await expect(component.relocate('../Names')).rejects.toThrow('vault-relative');
  await expect(component.relocate(TARGET)).rejects.toThrow('hidden');
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
});

it('can disable transport after synchronization fails without discarding local history', async () => {
  const component = await createComponent();
  await component.setSyncEnabled(true);
  const failure = vi.spyOn(SharedDataStore.prototype, 'synchronize').mockRejectedValueOnce(new Error('offline'));
  await expect(component.flush()).rejects.toThrow('offline');
  failure.mockRestore();
  await component.setSyncEnabled(false);
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.flush();
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  const reloaded = await createComponent();
  expect(reloaded.isSyncEnabled).toBe(false);
});

it('reverts failed enrollment to local-only and allows an explicit retry', async () => {
  const component = await createComponent();
  await app.vault.createFolder(ROOT);
  const failure = vi.spyOn(app.vault.adapter, 'list').mockRejectedValueOnce(new Error('offline'));
  await expect(component.setSyncEnabled(true)).rejects.toThrow('offline');
  expect(component.isSyncEnabled).toBe(false);
  failure.mockRestore();
  const reloaded = await createComponent();
  expect(reloaded.isSyncEnabled).toBe(false);
  await component.setSyncEnabled(true);
  expect(component.isSyncEnabled).toBe(true);
});

it('refuses operations on a component whose store has not loaded', async () => {
  const component = new OriginalAttachmentNamesComponent({
    app,
    consoleDebugComponent: strictProxy<ConsoleDebugComponent>({ consoleDebug: vi.fn() }),
    pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice: vi.fn() }),
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings }),
    storeFilePath: 'plugin-folder/original-attachment-names.json'
  });
  expect(component.transportRoots).toEqual([]);
  await expect(component.setSyncEnabled(true)).rejects.toThrow('not loaded');
  await expect(component.relocate('Names')).rejects.toThrow('Enable synchronization');
  component.load();
  components.push(component);
  const file = await app.vault.create('alpha.pdf', 'alpha');
  component.set(file.path, 'arrival.pdf');
  app.vault.trigger('delete', file);
  expect(component.get(file.path)).toBeUndefined();
});

it('ignores transport ancestors while renaming and deleting their real attachment siblings', async () => {
  const component = await createComponent();
  await app.vault.createFolder(ANCHOR);
  const file = await app.vault.create(`${ANCHOR}/alpha.pdf`, 'alpha');
  component.set(file.path, 'arrival.pdf');
  const folder = app.vault.getFolderByPath(ANCHOR);
  expect(folder).not.toBeNull();
  if (!folder) {
    throw new Error('Test folder missing');
  }
  await app.vault.rename(folder, 'Moved data');
  expect(component.get('Moved data/alpha.pdf')).toBe('arrival.pdf');
  await app.vault.rename(folder, ANCHOR);
  await app.fileManager.trashFile(folder);
  expect(component.get(`${ANCHOR}/alpha.pdf`)).toBeUndefined();
  expect(component.size).toBe(0);
});

it('does not turn transport-only ancestor operations into attachment observations', async () => {
  const component = await createComponent();
  await app.vault.createFolder(ANCHOR);
  await component.setSyncEnabled(true);
  const publication = vi.spyOn(SharedDataStore.prototype, 'setMany');
  const folder = app.vault.getFolderByPath(ANCHOR);
  expect(folder).not.toBeNull();
  if (!folder) {
    throw new Error('Transport folder missing');
  }
  await component.setSyncEnabled(false);
  await app.vault.createFolder(`${ROOT}/devices/alpha`);
  const document = await app.vault.create(`${ROOT}/devices/alpha/log-1.json`, 'metadata');
  await app.vault.rename(folder, 'Moved data');
  await app.fileManager.trashFile(document);
  await app.fileManager.trashFile(folder);
  await component.flush();
  expect(publication).not.toHaveBeenCalled();
});

it.each(['', '/', '../alpha', 'alpha/../bravo', 'C:/alpha', String.raw`alpha\bravo`, 'alpha//bravo', 'alpha/{{token}}', 'alpha ', 'alpha/./bravo'])('rejects an unsafe static folder: %s', (folder) => {
  expect(validatePluginDataFolder(folder, true)).toContain('vault-relative');
});

it('requires explicit hidden-folder permission but accepts visible nested folders', () => {
  expect(validatePluginDataFolder('99-Meta/.names', false)).toContain('hidden');
  expect(validatePluginDataFolder('99-Meta/.names', true)).toBeNull();
  expect(validatePluginDataFolder('99-Meta/Names', false)).toBeNull();
});

it('handles a folder-only deletion event while keeping metadata paths and unrelated names', async () => {
  const component = await createComponent();
  const folder = await app.vault.createFolder(ANCHOR);
  component.set(`${ANCHOR}/alpha.pdf`, 'arrival.pdf');
  component.set('elsewhere/bravo.pdf', 'bravo.pdf');
  // Old imported histories can contain metadata paths; transport events must not rewrite those records.
  component.set(`${ROOT}/alpha.json`, 'alpha.json');
  app.vault.trigger('delete', folder);
  expect(component.get(`${ANCHOR}/alpha.pdf`)).toBeUndefined();
  expect(component.get('elsewhere/bravo.pdf')).toBe('bravo.pdf');
  expect(component.get(`${ROOT}/alpha.json`)).toBe('alpha.json');
});

it('keeps queued consent changes in call order, so the last disable wins', async () => {
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  const enable = component.setSyncEnabled(true);
  const disable = component.setSyncEnabled(false);
  await Promise.all([enable, disable]);
  expect(component.isSyncEnabled).toBe(false);
  const reloaded = await createComponent();
  expect(reloaded.isSyncEnabled).toBe(false);
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('refuses conflicting destination bytes, preserves sibling plugin data, and retries after recovery', async () => {
  settings.shouldAllowHiddenPluginDataFolder = true;
  const component = await createComponent();
  await component.setSyncEnabled(true);
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.flush();
  const devices = await app.vault.adapter.list(`${ROOT}/devices`);
  const documents = await app.vault.adapter.list(String(devices.folders[0]));
  const source = documents.files.find((path) => path.includes('/log-'));
  if (!source) {
    throw new Error('Source history not published');
  }
  const target = `${TARGET_ROOT}${source.slice(ROOT.length)}`;
  await app.vault.createFolder(target.slice(0, target.lastIndexOf('/')));
  await app.vault.adapter.write(target, 'conflicting bytes');
  const sibling = `${TARGET}/other-plugin/data.json`;
  await app.vault.createFolder(`${TARGET}/other-plugin`);
  await app.vault.adapter.write(sibling, 'sibling data');
  await expect(component.relocate(TARGET)).rejects.toThrow();
  expect(await app.vault.adapter.read(target)).toBe('conflicting bytes');
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  await component.setSyncEnabled(false);
  const reloaded = await createComponent();
  expect(reloaded.transportRoots).toContain(TARGET_ROOT);
  expect(reloaded.isSyncEnabled).toBe(false);
  await app.vault.adapter.remove(target);
  await component.setSyncEnabled(true);
  await component.relocate(TARGET);
  expect(await app.vault.adapter.read(target)).toBe(await app.vault.adapter.read(source));
  expect(await app.vault.adapter.read(sibling)).toBe('sibling data');
  expect(component.transportRoots).toContain(TARGET_ROOT);
});

it('excludes acknowledgement and sibling events, but reacts to JSON journals and migration discoveries', async () => {
  await createComponent();
  vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
  try {
    const synchronize = vi.spyOn(SharedDataStore.prototype, 'synchronize');
    app.vault.trigger('raw', `${ROOT}/devices/alpha/have.json`);
    app.vault.trigger('raw', `${ROOT}-sibling/devices/alpha/log-1.json`);
    await vi.advanceTimersByTimeAsync(1000);
    await waitForAllAsyncOperations();
    expect(synchronize).not.toHaveBeenCalled();
    app.vault.trigger('raw', `${ROOT}/devices/alpha/log-1.json`);
    await vi.advanceTimersByTimeAsync(1000);
    await waitForAllAsyncOperations();
    expect(synchronize).toHaveBeenCalledOnce();
    app.vault.trigger('raw', `${ROOT}/locations-v1/alpha.json`);
    await vi.advanceTimersByTimeAsync(1000);
    await waitForAllAsyncOperations();
    expect(synchronize).toHaveBeenCalledTimes(2);
  } finally {
    vi.useRealTimers();
  }
});

it.each(['NUL', 'alpha.'])('rejects a folder that cannot be synchronized to Windows: %s', (folder) => {
  expect(validatePluginDataFolder(folder, true)).toContain('vault-relative');
});

it.each([null, 1, ['valid', 1]])('fails closed on damaged device-local transport exclusions: %j', async (value) => {
  const local = await LocalDataStore.open({ pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1', vaultId: app.appId });
  await local.set('original-name-requested-transport-roots-v1', value);
  local.close();
  await expect(createComponent()).rejects.toThrow('Invalid requested');
});

it('starts fresh setup directly in JSON and retains the provider restriction across reload', async () => {
  settings.shouldAllowHiddenPluginDataFolder = true;
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.setSyncEnabled(true, { shouldUseObsidianSync: true });
  const devices = await app.vault.adapter.list(`${ROOT}/devices`);
  const documents = await app.vault.adapter.list(String(devices.folders[0]));
  expect(documents.files.length).toBeGreaterThan(0);
  expect(documents.files.every((path) => path.endsWith('.json'))).toBe(true);
  const reloaded = await createComponent();
  expect(reloaded.isSyncEnabled).toBe(true);
  await expect(reloaded.relocate(TARGET)).rejects.toThrow('hidden history');
  expect(await app.vault.adapter.exists(TARGET_ROOT)).toBe(false);
  await reloaded.relocate('99-Meta/Names');
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('checks discovered hidden readers before enrolling a new Obsidian Sync device', async () => {
  settings.shouldAllowHiddenPluginDataFolder = true;
  const first = await createComponent();
  first.set('assets/alpha.pdf', 'arrival.pdf');
  await first.setSyncEnabled(true);
  await first.relocate(TARGET);
  vi.stubGlobal('indexedDB', new IDBFactory());
  const second = await createComponent();
  await expect(second.setSyncEnabled(true, { shouldUseObsidianSync: true })).rejects.toThrow('hidden history');
  expect(second.isSyncEnabled).toBe(false);
  expect(second.transportRoots).toContain(TARGET_ROOT);
  await second.setSyncEnabled(true);
  expect(second.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('opens a fresh install at the new default folder, even after it has recorded names locally', async () => {
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.flush();
  const reloaded = await createComponent();
  await reloaded.setSyncEnabled(true);
  expect(await app.vault.adapter.exists(ROOT)).toBe(true);
  expect(await app.vault.adapter.exists(LEGACY_PLUGIN_DATA_FOLDER)).toBe(false);
  expect(await reloaded.getExistingStoreFolders()).toEqual([ANCHOR]);
});

async function publishLegacyHistory(): Promise<void> {
  // Written by another device, which shares the vault but not IndexedDB with any other component here.
  vi.stubGlobal('indexedDB', new IDBFactory());
  const local = await LocalDataStore.open({ pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1', vaultId: app.appId });
  const shared = await SharedDataStore.open({ adapter: app.vault.adapter, kind: 'last-write-wins', local, pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1' });
  await shared.set('legacy-alpha', { fileName: 'arrival.pdf', kind: 'arrival', path: 'assets/alpha.pdf', time: 1 });
  local.close();
  // A component created next is a new device again.
  vi.stubGlobal('indexedDB', new IDBFactory());
}

it('joins the earlier folder when a new device opens a vault that already holds its history', async () => {
  await publishLegacyHistory();
  const component = await createComponent();
  expect(component.transportRoots).toContain(LEGACY_ROOT);
  await component.setSyncEnabled(true);
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(await app.vault.adapter.exists(ROOT)).toBe(false);
  expect(await component.getExistingStoreFolders()).toEqual([LEGACY_PLUGIN_DATA_FOLDER]);
});

it('joins the earlier folder when the vault delivers its history after the device opened', async () => {
  const lateDevice = await createComponent();
  const lateIndexedDatabase = window.indexedDB;
  await publishLegacyHistory();
  vi.stubGlobal('indexedDB', lateIndexedDatabase);
  await lateDevice.setSyncEnabled(true);
  expect(lateDevice.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(await app.vault.adapter.exists(ROOT)).toBe(false);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('keeps the new folder once synchronization started there, whatever arrives later', async () => {
  const component = await createComponent();
  await component.setSyncEnabled(true);
  const ownIndexedDatabase = window.indexedDB;
  await publishLegacyHistory();
  vi.stubGlobal('indexedDB', ownIndexedDatabase);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/alpha.pdf')).toBeUndefined();
  expect(reloaded.transportRoots).not.toContain(LEGACY_ROOT);
});

it('fails closed on a damaged device-local anchor folder', async () => {
  const local = await LocalDataStore.open({ pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1', vaultId: app.appId });
  await local.set('original-name-anchor-folder-v1', 1);
  local.close();
  await expect(createComponent()).rejects.toThrow('Invalid original-name anchor folder');
});

it('tells listeners about storage changes until they stop listening', async () => {
  const component = await createComponent();
  const callback = vi.fn();
  const stop = component.onStorageChanged(callback);
  await component.setSyncEnabled(true);
  expect(callback).toHaveBeenCalledOnce();
  await component.relocate('99-Meta/Names');
  expect(callback).toHaveBeenCalledTimes(2);
  expect(await component.getExistingStoreFolders()).toEqual([ANCHOR, '99-Meta/Names']);
  stop();
  await component.setSyncEnabled(false);
  expect(callback).toHaveBeenCalledTimes(2);
});
