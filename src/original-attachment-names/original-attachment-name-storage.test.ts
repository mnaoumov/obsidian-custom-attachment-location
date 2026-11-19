import type { ConsoleDebugComponent } from '@mnaoumov/obsidian-lib/components/console-debug-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { Mock } from 'vitest';

import { DataStoreLocations } from '@mnaoumov/obsidian-lib/data-stores/data-store-locations';
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
  PLUGIN_DATA_FOLDER_README,
  PLUGIN_DATA_SUBFOLDER_README
} from './plugin-data-folder-exclusion-component.ts';
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
const MOVED_LEGACY = `!Meta/${LEGACY_PLUGIN_DATA_FOLDER}`;
const MOVED_LEGACY_ROOT = `${MOVED_LEGACY}/obsidian-custom-attachment-location/original-attachment-names-v1`;
let mockApp: App;
let app: ReturnType<App['asOriginalType__']>;
let settings: PluginSettings;
let components: OriginalAttachmentNamesComponent[];
let showNotice: Mock<PluginNoticeComponent['showNotice']>;

async function createComponent(): Promise<OriginalAttachmentNamesComponent> {
  const component = new OriginalAttachmentNamesComponent({
    app,
    consoleDebugComponent: strictProxy<ConsoleDebugComponent>({ consoleDebug: vi.fn() }),
    pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice }),
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings }),
    storeFilePath: 'plugin-folder/original-attachment-names.json'
  });
  await component.loadFromDisk();
  component.load();
  components.push(component);
  return component;
}

beforeEach(() => {
  mockApp = App.createConfigured__();
  app = mockApp.asOriginalType__();
  settings = new PluginSettings();
  components = [];
  showNotice = vi.fn();
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
  expect(second.get('assets/alpha.pdf')).toBeNull();
  await second.setSyncEnabled(true);
  expect(second.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('moves the history into a hidden folder, leaving no folder behind, and keeps it there across reload', async () => {
  settings.shouldAllowHiddenPluginDataFolder = true;
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.setSyncEnabled(true);
  await app.vault.adapter.write(`${ANCHOR}/README.md`, PLUGIN_DATA_FOLDER_README);
  // A file the operating system leaves behind is no reason to keep the former folder.
  await app.vault.adapter.write(`${ANCHOR}/.DS_Store`, '');
  await component.relocate(TARGET);
  await component.relocate(TARGET);
  expect(component.transportRoots).toContain(TARGET_ROOT);
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(await component.getExistingStoreFolders()).toEqual([TARGET]);
  await component.setSyncEnabled(false);
  const reloaded = await createComponent();
  expect(reloaded.transportRoots).toContain(TARGET_ROOT);
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(reloaded.isSyncEnabled).toBe(false);
  await reloaded.setSyncEnabled(true);
  expect(await reloaded.getExistingStoreFolders()).toEqual([TARGET]);
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
});

it('keeps a former folder that holds the user\'s own files, removing only the plugin\'s subfolder', async () => {
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await app.vault.adapter.mkdir(ANCHOR);
  await app.vault.adapter.write(`${ANCHOR}/notes.md`, 'mine');
  await component.setSyncEnabled(true);
  await app.vault.adapter.write(`${ANCHOR}/obsidian-custom-attachment-location/README.md`, PLUGIN_DATA_SUBFOLDER_README);
  await component.relocate('99-Meta/Names');
  expect(await app.vault.adapter.read(`${ANCHOR}/notes.md`)).toBe('mine');
  expect(await app.vault.adapter.exists(`${ANCHOR}/obsidian-custom-attachment-location`)).toBe(false);
  expect(await component.getExistingStoreFolders()).toEqual(['99-Meta/Names']);
});

it('keeps a former folder that the destination sits inside', async () => {
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.setSyncEnabled(true);
  await component.relocate(`${ANCHOR}/Inner`);
  expect(await component.getExistingStoreFolders()).toEqual([`${ANCHOR}/Inner`]);
  expect(await app.vault.adapter.exists(`${ANCHOR}/obsidian-custom-attachment-location`)).toBe(false);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('tolerates a sync tool removing the emptied former folder before the move finishes', async () => {
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  await component.setSyncEnabled(true);
  const rename = app.vault.adapter.rename.bind(app.vault.adapter);
  vi.spyOn(app.vault.adapter, 'rename').mockImplementation(async (from, to) => {
    await rename(from, to);
    await app.vault.adapter.rmdir(from.slice(0, from.lastIndexOf('/')), true);
  });
  await component.relocate('99-Meta/Names');
  expect(await component.getExistingStoreFolders()).toEqual(['99-Meta/Names']);
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
});

it('refuses a destination inside the history itself', async () => {
  const component = await createComponent();
  await component.setSyncEnabled(true);
  await expect(component.relocate(`${ROOT}/inner`)).rejects.toThrow('inside the history folder');
  expect(await component.getExistingStoreFolders()).toEqual([ANCHOR]);
});

it('lets another device follow the move without recreating the former folder', async () => {
  const first = await createComponent();
  first.set('assets/alpha.pdf', 'arrival.pdf');
  await first.setSyncEnabled(true);
  vi.stubGlobal('indexedDB', new IDBFactory());
  const second = await createComponent();
  await second.setSyncEnabled(true);
  expect(second.get('assets/alpha.pdf')).toBe('arrival.pdf');
  await first.relocate('99-Meta/Names');
  first.set('assets/bravo.pdf', 'bravo.pdf');
  await first.flush();
  second.set('assets/charlie.pdf', 'charlie.pdf');
  await second.flush();
  expect(second.get('assets/bravo.pdf')).toBe('bravo.pdf');
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(await second.getExistingStoreFolders()).toEqual(['99-Meta/Names']);
  await first.flush();
  expect(first.get('assets/charlie.pdf')).toBe('charlie.pdf');
  expect(showNotice).not.toHaveBeenCalled();
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
  expect(component.get(file.path)).toBeNull();
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
  expect(component.get(`${ANCHOR}/alpha.pdf`)).toBeNull();
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
  expect(component.get(`${ANCHOR}/alpha.pdf`)).toBeNull();
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

it('refuses a destination that holds a separate history, preserves sibling plugin data, and retries after recovery', async () => {
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
  const sourceText = await app.vault.adapter.read(source);
  const conflicting = `${TARGET_ROOT}/devices/other/log-1.json`;
  await app.vault.adapter.mkdir(`${TARGET_ROOT}/devices/other`);
  await app.vault.adapter.write(conflicting, 'separate history');
  const sibling = `${TARGET}/other-plugin/data.json`;
  await app.vault.adapter.mkdir(`${TARGET}/other-plugin`);
  await app.vault.adapter.write(sibling, 'sibling data');
  await expect(component.relocate(TARGET)).rejects.toThrow('separate original name history');
  expect(await app.vault.adapter.read(conflicting)).toBe('separate history');
  expect(await app.vault.adapter.read(source)).toBe(sourceText);
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  await component.setSyncEnabled(false);
  const reloaded = await createComponent();
  expect(reloaded.transportRoots).toContain(TARGET_ROOT);
  expect(reloaded.isSyncEnabled).toBe(false);
  await app.vault.adapter.rmdir(TARGET_ROOT, true);
  await component.setSyncEnabled(true);
  await component.relocate(TARGET);
  expect(await app.vault.adapter.read(`${TARGET_ROOT}${source.slice(ROOT.length)}`)).toBe(sourceText);
  expect(await app.vault.adapter.read(sibling)).toBe('sibling data');
  expect(await app.vault.adapter.exists(ROOT)).toBe(false);
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
  expect(component.isObsidianSyncProvider).toBe(false);
  await component.setSyncEnabled(true, { shouldUseObsidianSync: true });
  expect(component.isObsidianSyncProvider).toBe(true);
  const devices = await app.vault.adapter.list(`${ROOT}/devices`);
  const documents = await app.vault.adapter.list(String(devices.folders[0]));
  expect(documents.files.length).toBeGreaterThan(0);
  expect(documents.files.every((path) => path.endsWith('.json'))).toBe(true);
  const reloaded = await createComponent();
  expect(reloaded.isSyncEnabled).toBe(true);
  expect(reloaded.isObsidianSyncProvider).toBe(true);
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
  expect(reloaded.get('assets/alpha.pdf')).toBeNull();
  expect(reloaded.transportRoots).not.toContain(LEGACY_ROOT);
});

it('fails closed on a damaged device-local anchor folder', async () => {
  const local = await LocalDataStore.open({ pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1', vaultId: app.appId });
  await local.set('original-name-anchor-folder-v1', 1);
  local.close();
  await expect(createComponent()).rejects.toThrow('Invalid original-name anchor folder');
});

async function moveFolder(from: string, to: string): Promise<void> {
  // Real Obsidian learns about the store's folders from its file watcher; the mock adapter needs a re-sync.
  mockApp.vault.reconcile__();
  const folder = app.vault.getFolderByPath(from);
  if (!folder) {
    throw new Error(`Folder missing: ${from}`);
  }
  const parent = to.slice(0, to.lastIndexOf('/'));
  if (parent && !app.vault.getFolderByPath(parent)) {
    await app.vault.createFolder(parent);
  }
  await app.vault.rename(folder, to);
}

async function publishOwnLegacyHistory(): Promise<void> {
  // The replica stays in this IndexedDB, so the next component is the device that wrote it, under an earlier version.
  const local = await LocalDataStore.open({ pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1', vaultId: app.appId });
  const shared = await SharedDataStore.open({ adapter: app.vault.adapter, kind: 'last-write-wins', local, pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1' });
  await shared.set('legacy-alpha', { fileName: 'arrival.pdf', kind: 'arrival', path: 'assets/alpha.pdf', time: 1 });
  local.close();
}

it('follows history whose folder was moved while the plugin was not running', async () => {
  await publishOwnLegacyHistory();
  await moveFolder(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  const component = await createComponent();
  expect(component.isSyncEnabled).toBe(true);
  expect(component.transportRoots).toContain(MOVED_LEGACY_ROOT);
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(await app.vault.adapter.exists(LEGACY_PLUGIN_DATA_FOLDER)).toBe(false);
  expect(await component.getExistingStoreFolders()).toEqual([MOVED_LEGACY]);
  expect(showNotice).not.toHaveBeenCalled();
});

it('follows history whose folder is moved while the plugin runs', async () => {
  await publishOwnLegacyHistory();
  const component = await createComponent();
  const callback = vi.fn();
  component.onStorageChanged(callback);
  await moveFolder(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(callback).toHaveBeenCalledOnce();
  expect(await app.vault.adapter.exists(LEGACY_PLUGIN_DATA_FOLDER)).toBe(false);
  expect(component.transportRoots).toContain(MOVED_LEGACY_ROOT);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/bravo.pdf')).toBe('bravo.pdf');
  expect(reloaded.transportRoots).toContain(MOVED_LEGACY_ROOT);
});

it('lets a new device join history that another device moved out of the default folders', async () => {
  await publishLegacyHistory();
  await moveFolder(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  const component = await createComponent();
  await component.setSyncEnabled(true);
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(await app.vault.adapter.exists(ROOT)).toBe(false);
  expect(await component.getExistingStoreFolders()).toEqual([MOVED_LEGACY]);
});

async function moveFolderOutsideIndex(from: string, to: string): Promise<void> {
  // An exclusion plugin such as `Advanced Exclude` hides the destination from the vault index; only the disk has it.
  const parent = to.slice(0, to.lastIndexOf('/'));
  if (parent && !await app.vault.adapter.exists(parent)) {
    await app.vault.adapter.mkdir(parent);
  }
  await app.vault.adapter.rename(from, to);
  expect(app.vault.getFolderByPath(`${to}/obsidian-custom-attachment-location/original-attachment-names-v1`)).toBeNull();
}

it('follows history moved while the plugin was not running into a folder the vault index hides', async () => {
  await publishOwnLegacyHistory();
  await moveFolderOutsideIndex(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  const component = await createComponent();
  expect(component.transportRoots).toContain(MOVED_LEGACY_ROOT);
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(await app.vault.adapter.exists(LEGACY_PLUGIN_DATA_FOLDER)).toBe(false);
  expect(showNotice).not.toHaveBeenCalled();
});

it('follows history moved while the plugin runs into a folder the vault index hides', async () => {
  await publishOwnLegacyHistory();
  const component = await createComponent();
  await moveFolderOutsideIndex(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(await app.vault.adapter.exists(LEGACY_PLUGIN_DATA_FOLDER)).toBe(false);
  expect(component.transportRoots).toContain(MOVED_LEGACY_ROOT);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/bravo.pdf')).toBe('bravo.pdf');
});

it('lets a new device join, when it enables synchronization, history moved into a folder the vault index hides', async () => {
  await publishLegacyHistory();
  await moveFolderOutsideIndex(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  const getAllFolders = vi.spyOn(app.vault, 'getAllFolders');
  const component = await createComponent();
  // Loading reads only the index, so an undecided device does not walk the vault at every start.
  expect(component.transportRoots).not.toContain(MOVED_LEGACY_ROOT);
  expect(getAllFolders).toHaveBeenCalled();
  await component.setSyncEnabled(true);
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(await app.vault.adapter.exists(ROOT)).toBe(false);
  expect(component.transportRoots).toContain(MOVED_LEGACY_ROOT);
});

it('skips dot folders and node_modules when looking for moved history on disk', async () => {
  await publishOwnLegacyHistory();
  await moveFolderOutsideIndex(LEGACY_PLUGIN_DATA_FOLDER, `.trash/${LEGACY_PLUGIN_DATA_FOLDER}`);
  await app.vault.adapter.mkdir(`node_modules/x/${LEGACY_ROOT}`);
  const component = await createComponent();
  expect(component.transportRoots).toContain(LEGACY_ROOT);
  expect(component.transportRoots).not.toContain(`.trash/${LEGACY_ROOT}`);
});

it('walks past a folder that disappears while it looks for moved history on disk', async () => {
  await publishOwnLegacyHistory();
  await moveFolderOutsideIndex(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  await app.vault.adapter.mkdir('Vanishing');
  const list = app.vault.adapter.list.bind(app.vault.adapter);
  vi.spyOn(app.vault.adapter, 'list').mockImplementation(async (path) => {
    if (path === 'Vanishing') {
      throw new Error('ENOENT');
    }
    return await list(path);
  });
  const component = await createComponent();
  expect(component.transportRoots).toContain(MOVED_LEGACY_ROOT);
});

it('follows no folder when the history is found in more than one', async () => {
  await publishOwnLegacyHistory();
  await moveFolder(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  await app.vault.createFolder(`Copy/${MOVED_LEGACY_ROOT}`);
  const component = await createComponent();
  expect(component.transportRoots).toContain(LEGACY_ROOT);
  expect(component.transportRoots).not.toContain(MOVED_LEGACY_ROOT);
});

it('waits for a relocation record that has not fully arrived before following moved history', async () => {
  await publishOwnLegacyHistory();
  await app.vault.adapter.mkdir(`${LEGACY_ROOT}/locations-v1`);
  await app.vault.adapter.write(`${LEGACY_ROOT}/locations-v1/partial.json`, '{"format":1,"payload":');
  await moveFolder(LEGACY_PLUGIN_DATA_FOLDER, MOVED_LEGACY);
  const component = await createComponent();
  expect(showNotice).toHaveBeenCalledOnce();
  expect(component.transportRoots).not.toContain(MOVED_LEGACY_ROOT);
  await component.flush();
  expect(await app.vault.adapter.exists(LEGACY_PLUGIN_DATA_FOLDER)).toBe(false);
});

const MOVED_ANCHOR = `!Meta/${ANCHOR}`;
const MOVED_ANCHOR_ROOT = `${MOVED_ANCHOR}/obsidian-custom-attachment-location/original-attachment-names-v1`;

interface RelocationRecordDocument {
  readonly payload: Record<string, unknown>;
}

async function rewriteMovedRelocationRecords(rewrite: (payload: Record<string, unknown>) => void): Promise<void> {
  const listing = await app.vault.adapter.list(`${MOVED_ANCHOR_ROOT}/locations-v1`);
  expect(listing.files.length).toBeGreaterThan(0);
  for (const path of listing.files) {
    const document = JSON.parse(await app.vault.adapter.read(path)) as RelocationRecordDocument;
    rewrite(document.payload);
    await app.vault.adapter.write(path, JSON.stringify(document));
  }
}

async function setUpRelocatedHistory(destination = '99-Meta/Names'): Promise<OriginalAttachmentNamesComponent> {
  const component = await createComponent();
  component.set('assets/alpha.pdf', 'arrival.pdf');
  // Setup records its switch to JSON at the anchor, naming the anchor's folder, which a move then leaves behind.
  await component.setSyncEnabled(true);
  // An earlier version relocated by copying, which left the history in two folders.
  await new DataStoreLocations({ adapter: app.vault.adapter, folder: ANCHOR, format: 'markdown', pluginId: 'obsidian-custom-attachment-location', storeId: 'original-attachment-names-v1' })
    .relocate({ folder: destination, format: 'json' });
  await component.flush();
  return component;
}

it('gathers copied history into the newest folder when that is the one applied', async () => {
  const component = await setUpRelocatedHistory();
  // Indexed folders go to the trash through the vault.
  mockApp.vault.reconcile__();
  await component.relocate('99-Meta/Names');
  expect(await component.getExistingStoreFolders()).toEqual(['99-Meta/Names']);
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(await app.vault.adapter.exists('99-Meta/Names/obsidian-custom-attachment-location/original-attachment-names-v1/locations-v1')).toBe(true);
  vi.stubGlobal('indexedDB', new IDBFactory());
  const newDevice = await createComponent();
  await newDevice.setSyncEnabled(true);
  expect(newDevice.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(await newDevice.getExistingStoreFolders()).toEqual(['99-Meta/Names']);
});

it('gathers copied history nested in the original folder, using the vault trash when the system trash refuses', async () => {
  const component = await setUpRelocatedHistory(`${ANCHOR}/Nested`);
  Reflect.set(app.vault.adapter, 'isSystemTrashAvailable__', false);
  await component.relocate('Archive/History');
  expect(await component.getExistingStoreFolders()).toEqual(['Archive/History']);
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(await app.vault.adapter.exists('.trash')).toBe(true);
  expect(component.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('follows a moved folder whose copied history sat inside it', async () => {
  const component = await setUpRelocatedHistory(`${ANCHOR}/Nested`);
  await moveFolder(ANCHOR, MOVED_ANCHOR);
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(showNotice).not.toHaveBeenCalled();
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(component.transportRoots).toContain(MOVED_ANCHOR_ROOT);
  expect(await component.getExistingStoreFolders()).toEqual([MOVED_ANCHOR, `${MOVED_ANCHOR}/Nested`]);
});

it('gathers history that an earlier version copied into two folders into the one applied', async () => {
  const component = await setUpRelocatedHistory();
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(await component.getExistingStoreFolders()).toEqual([ANCHOR, '99-Meta/Names']);
  await component.relocate('Archive/History');
  expect(await component.getExistingStoreFolders()).toEqual(['Archive/History']);
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(await app.vault.adapter.exists('99-Meta/Names')).toBe(false);
  component.set('assets/charlie.pdf', 'charlie.pdf');
  await component.flush();
  const root = 'Archive/History/obsidian-custom-attachment-location/original-attachment-names-v1';
  const devices = await app.vault.adapter.list(`${root}/devices`);
  const documents = await app.vault.adapter.list(String(devices.folders[0]));
  expect(documents.files.every((path) => path.endsWith('.json'))).toBe(true);
  vi.stubGlobal('indexedDB', new IDBFactory());
  const newDevice = await createComponent();
  await newDevice.setSyncEnabled(true);
  expect(newDevice.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(newDevice.get('assets/bravo.pdf')).toBe('bravo.pdf');
  expect(newDevice.get('assets/charlie.pdf')).toBe('charlie.pdf');
  expect(await newDevice.getExistingStoreFolders()).toEqual(['Archive/History']);
});

it('moves gathered history back to a folder it used before', async () => {
  const component = await setUpRelocatedHistory();
  await component.relocate(ANCHOR);
  expect(await component.getExistingStoreFolders()).toEqual([ANCHOR]);
  expect(await app.vault.adapter.exists('99-Meta/Names')).toBe(false);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
  await reloaded.relocate('99-Meta/Names');
  expect(await reloaded.getExistingStoreFolders()).toEqual(['99-Meta/Names']);
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
});

it('follows history moved after a relocation, whose records name the anchor they were written at', async () => {
  const component = await setUpRelocatedHistory();
  await moveFolder(ANCHOR, MOVED_ANCHOR);
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(showNotice).not.toHaveBeenCalled();
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(component.transportRoots).toContain(MOVED_ANCHOR_ROOT);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/alpha.pdf')).toBe('arrival.pdf');
  expect(reloaded.get('assets/bravo.pdf')).toBe('bravo.pdf');
  await reloaded.setSyncEnabled(false);
  await reloaded.setSyncEnabled(true);
  expect(reloaded.isSyncEnabled).toBe(true);
  await reloaded.flush();
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  const storeFolders = await reloaded.getExistingStoreFolders();
  expect(new Set(storeFolders)).toEqual(new Set(['99-Meta/Names', MOVED_ANCHOR]));
  expect(storeFolders).toHaveLength(2);
  expect(showNotice).not.toHaveBeenCalled();
});

it('follows history moved after a relocation whose records predate naming their anchor', async () => {
  const component = await setUpRelocatedHistory();
  await moveFolder(ANCHOR, MOVED_ANCHOR);
  await rewriteMovedRelocationRecords((payload) => {
    Reflect.deleteProperty(payload, 'anchor');
  });
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(showNotice).not.toHaveBeenCalled();
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(component.transportRoots).toContain(MOVED_ANCHOR_ROOT);
  const reloaded = await createComponent();
  expect(reloaded.get('assets/bravo.pdf')).toBe('bravo.pdf');
});

it('pauses synchronization rather than splitting moved history no single former folder explains', async () => {
  const component = await setUpRelocatedHistory();
  await moveFolder(ANCHOR, MOVED_ANCHOR);
  // Old records that each start at a different folder: the library cannot tell which one the anchor left.
  let recordIndex = 0;
  await rewriteMovedRelocationRecords((payload) => {
    Reflect.deleteProperty(payload, 'anchor');
    recordIndex++;
    payload['from'] = { folder: `Elsewhere ${String(recordIndex)}`, format: 'markdown' };
  });
  component.set('assets/bravo.pdf', 'bravo.pdf');
  await component.flush();
  expect(showNotice).toHaveBeenCalledOnce();
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  expect(component.get('assets/bravo.pdf')).toBe('bravo.pdf');
  const reloaded = await createComponent();
  expect(showNotice).toHaveBeenCalledTimes(2);
  await reloaded.flush();
  expect(await app.vault.adapter.exists(ANCHOR)).toBe(false);
  await reloaded.setSyncEnabled(false);
  await expect(reloaded.setSyncEnabled(true)).rejects.toThrow(`moved from ${ANCHOR} to ${MOVED_ANCHOR}`);
});

it('tells listeners about storage changes until they stop listening', async () => {
  const component = await createComponent();
  const callback = vi.fn();
  const stop = component.onStorageChanged(callback);
  await component.setSyncEnabled(true);
  expect(callback).toHaveBeenCalledOnce();
  await component.relocate('99-Meta/Names');
  expect(callback).toHaveBeenCalledTimes(2);
  expect(await component.getExistingStoreFolders()).toEqual(['99-Meta/Names']);
  stop();
  await component.setSyncEnabled(false);
  expect(callback).toHaveBeenCalledTimes(2);
});
