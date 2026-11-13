import { AsyncEvents } from '@mnaoumov/typescript-lib/async-events';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { waitForAllAsyncOperations } from '@mnaoumov/typescript-test-toolkit/async-operation-tracking';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { PluginSettings } from '../settings/plugin-settings.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

import {
  PLUGIN_DATA_FOLDER_DOCS_URL,
  PLUGIN_DATA_FOLDER_README,
  PLUGIN_DATA_SUBFOLDER_README,
  PluginDataFolderExclusionComponent
} from './plugin-data-folder-exclusion-component.ts';
import {
  DEFAULT_PLUGIN_DATA_FOLDER,
  LEGACY_PLUGIN_DATA_FOLDER,
  PLUGIN_DATA_FOLDER_README_HEADING,
  PLUGIN_DATA_SUBFOLDER_NAME
} from './plugin-data-folder.ts';

interface LayoutReadyTrigger {
  readonly onLayoutReady: () => void;
}

interface SettingsState {
  readonly effectiveValues: Pick<PluginSettings, 'pluginDataFolder'>;
}

const MANAGED_KEY = 'obsidian-custom-attachment-location:managed-ignore-filters-v1';

let app: ReturnType<App['asOriginalType__']>;
let events: AsyncEvents;
let settings: Pick<PluginSettings, 'pluginDataFolder'>;
let existingFolders: string[];
let isSyncEnabled: boolean;
let storageChangedCallbacks: (() => void)[];
let component: PluginDataFolderExclusionComponent;

function getFilters(): string[] {
  return castTo<null | string[] | undefined>(app.vault.getConfig('userIgnoreFilters')) ?? [];
}

function state(pluginDataFolder: string): SettingsState {
  return { effectiveValues: { pluginDataFolder } };
}

beforeEach(() => {
  app = App.createConfigured__().asOriginalType__();
  events = new AsyncEvents();
  settings = { pluginDataFolder: DEFAULT_PLUGIN_DATA_FOLDER };
  existingFolders = [];
  isSyncEnabled = true;
  storageChangedCallbacks = [];
  const originalAttachmentNamesComponent = strictProxy<OriginalAttachmentNamesComponent>({
    getExistingStoreFolders: () => Promise.resolve([...existingFolders]),
    get isSyncEnabled(): boolean {
      return isSyncEnabled;
    },
    onStorageChanged: (callback: () => void): () => void => {
      storageChangedCallbacks.push(callback);
      return () => {
        storageChangedCallbacks.splice(storageChangedCallbacks.indexOf(callback), 1);
      };
    }
  });
  const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
    on: castTo<PluginSettingsComponent['on']>(events.on.bind(events)),
    settings: castTo<PluginSettings>(settings)
  });
  component = new PluginDataFolderExclusionComponent({ app, originalAttachmentNamesComponent, pluginSettingsComponent });
});

afterEach(async () => {
  component.unload();
  await waitForAllAsyncOperations();
  vi.restoreAllMocks();
});

describe('PluginDataFolderExclusionComponent', () => {
  it('should exclude the setting folder while this device synchronizes, and write no README before the folder exists', async () => {
    await component.reconcile();

    expect(getFilters()).toEqual([`${DEFAULT_PLUGIN_DATA_FOLDER}/`]);
    expect(await app.vault.adapter.exists(DEFAULT_PLUGIN_DATA_FOLDER)).toBe(false);
  });

  it('should add nothing on a device that keeps its history locally', async () => {
    isSyncEnabled = false;

    await component.reconcile();

    expect(getFilters()).toEqual([]);
    expect(app.loadLocalStorage(MANAGED_KEY)).toBeNull();
  });

  it('should exclude every existing store folder and explain it with a README', async () => {
    isSyncEnabled = false;
    existingFolders = [LEGACY_PLUGIN_DATA_FOLDER, '99-Meta/Names'];
    await app.vault.createFolder(LEGACY_PLUGIN_DATA_FOLDER);
    await app.vault.createFolder('99-Meta/Names');

    await component.reconcile();

    expect(getFilters()).toEqual([`${LEGACY_PLUGIN_DATA_FOLDER}/`, '99-Meta/Names/']);
    expect(await app.vault.adapter.read(`${LEGACY_PLUGIN_DATA_FOLDER}/README.md`)).toBe(PLUGIN_DATA_FOLDER_README);
    expect(await app.vault.adapter.read('99-Meta/Names/README.md')).toBe(PLUGIN_DATA_FOLDER_README);
    expect(PLUGIN_DATA_FOLDER_README).toContain(PLUGIN_DATA_FOLDER_DOCS_URL);
  });

  it('should restore an edited README and leave an unchanged one alone', async () => {
    existingFolders = [DEFAULT_PLUGIN_DATA_FOLDER];
    await app.vault.createFolder(DEFAULT_PLUGIN_DATA_FOLDER);
    const path = `${DEFAULT_PLUGIN_DATA_FOLDER}/README.md`;
    await app.vault.adapter.write(path, `${PLUGIN_DATA_FOLDER_README_HEADING}\n\nedited by hand`);

    await component.reconcile();
    expect(await app.vault.adapter.read(path)).toBe(PLUGIN_DATA_FOLDER_README);

    const write = vi.spyOn(app.vault.adapter, 'write');
    await component.reconcile();
    expect(write).not.toHaveBeenCalled();
  });

  it('should claim only its subfolder in a folder that holds the user\'s own files, and leave their README alone', async () => {
    isSyncEnabled = false;
    existingFolders = ['Work notes'];
    await app.vault.adapter.mkdir(`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/original-attachment-names-v1`);
    await app.vault.adapter.write('Work notes/Note.md', 'my note');
    await app.vault.adapter.write('Work notes/README.md', 'my own readme');

    await component.reconcile();

    expect(getFilters()).toEqual([`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/`]);
    expect(await app.vault.adapter.read('Work notes/README.md')).toBe('my own readme');
    expect(await app.vault.adapter.read(`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/README.md`)).toBe(PLUGIN_DATA_SUBFOLDER_README);
  });

  it('should treat a user README alone as the user\'s content, and never write over it', async () => {
    isSyncEnabled = false;
    existingFolders = ['Work notes'];
    await app.vault.adapter.mkdir(`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/original-attachment-names-v1`);
    await app.vault.adapter.write('Work notes/README.md', 'my own readme');

    await component.reconcile();

    expect(getFilters()).toEqual([`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/`]);
    expect(await app.vault.adapter.read('Work notes/README.md')).toBe('my own readme');
  });

  it('should remove the README an earlier version wrote into a folder that holds the user\'s own files', async () => {
    isSyncEnabled = false;
    existingFolders = ['Work notes'];
    await app.vault.adapter.mkdir(`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/original-attachment-names-v1`);
    await app.vault.adapter.write('Work notes/Note.md', 'my note');
    await app.vault.adapter.write('Work notes/README.md', PLUGIN_DATA_FOLDER_README);

    await component.reconcile();

    expect(await app.vault.adapter.exists('Work notes/README.md')).toBe(false);
    expect(await app.vault.adapter.read('Work notes/Note.md')).toBe('my note');
  });

  it('should claim the whole folder again once it holds only plugin data, ignoring hidden system files', async () => {
    isSyncEnabled = false;
    existingFolders = ['Work notes'];
    await app.vault.adapter.mkdir(`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/original-attachment-names-v1`);
    await app.vault.adapter.write('Work notes/Note.md', 'my note');
    await component.reconcile();
    expect(await app.vault.adapter.exists(`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/README.md`)).toBe(true);

    await app.vault.adapter.remove('Work notes/Note.md');
    await app.vault.adapter.write('Work notes/.DS_Store', '');
    await component.reconcile();

    expect(getFilters()).toEqual(['Work notes/']);
    expect(await app.vault.adapter.read('Work notes/README.md')).toBe(PLUGIN_DATA_FOLDER_README);
    expect(await app.vault.adapter.exists(`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/README.md`)).toBe(false);
  });

  it('should exclude only its subfolder of an existing user folder the setting names while this device synchronizes', async () => {
    settings.pluginDataFolder = 'Work notes';
    await app.vault.adapter.mkdir('Work notes/Projects');

    await component.reconcile();

    expect(getFilters()).toEqual([`Work notes/${PLUGIN_DATA_SUBFOLDER_NAME}/`]);
    expect(await app.vault.adapter.exists('Work notes/README.md')).toBe(false);
  });

  it('should skip hidden folders, which Obsidian never indexes, but still explain them', async () => {
    existingFolders = ['99-Meta/.names'];
    settings.pluginDataFolder = '99-Meta/.names';
    await app.vault.adapter.mkdir('99-Meta/.names');

    await component.reconcile();

    expect(getFilters()).toEqual([]);
    expect(await app.vault.adapter.read('99-Meta/.names/README.md')).toBe(PLUGIN_DATA_FOLDER_README);
  });

  it('should replace its own entry when the setting changes, keeping the user\'s entries in place', async () => {
    app.vault.setConfig('userIgnoreFilters', ['Private/']);
    await component.reconcile();
    expect(getFilters()).toEqual(['Private/', `${DEFAULT_PLUGIN_DATA_FOLDER}/`]);

    settings.pluginDataFolder = 'Meta/Sync data';
    await component.reconcile();

    expect(getFilters()).toEqual(['Private/', 'Meta/Sync data/']);
    expect(app.loadLocalStorage(MANAGED_KEY)).toEqual(['Meta/Sync data/']);
  });

  it('should never remove an entry the user already had', async () => {
    app.vault.setConfig('userIgnoreFilters', [`${DEFAULT_PLUGIN_DATA_FOLDER}/`]);
    await component.reconcile();
    expect(app.loadLocalStorage(MANAGED_KEY)).toBeNull();

    settings.pluginDataFolder = 'Meta/Sync data';
    await component.reconcile();

    expect(getFilters()).toEqual([`${DEFAULT_PLUGIN_DATA_FOLDER}/`, 'Meta/Sync data/']);
  });

  it('should drop its entry once synchronization is turned off and no store folder exists', async () => {
    await component.reconcile();
    isSyncEnabled = false;

    await component.reconcile();

    expect(getFilters()).toEqual([]);
    expect(app.loadLocalStorage(MANAGED_KEY)).toBeNull();
  });

  it('should not rewrite the vault config when nothing changed', async () => {
    await component.reconcile();
    const setConfig = vi.spyOn(app.vault, 'setConfig');

    await component.reconcile();

    expect(setConfig).not.toHaveBeenCalled();
  });

  it('should ignore damaged remembered entries', async () => {
    app.saveLocalStorage(MANAGED_KEY, 'damaged');
    app.vault.setConfig('userIgnoreFilters', ['damaged']);

    await component.reconcile();

    expect(getFilters()).toEqual(['damaged', `${DEFAULT_PLUGIN_DATA_FOLDER}/`]);
  });

  it('should follow settings changes, reloads and storage changes once loaded', async () => {
    component.load();
    castTo<LayoutReadyTrigger>(component).onLayoutReady();
    await waitForAllAsyncOperations();
    expect(getFilters()).toEqual([`${DEFAULT_PLUGIN_DATA_FOLDER}/`]);

    settings.pluginDataFolder = 'Meta/Sync data';
    await events.triggerAsync('saveSettings', state('Meta/Sync data'), state('Meta/Sync data'));
    await waitForAllAsyncOperations();
    expect(getFilters()).toEqual([`${DEFAULT_PLUGIN_DATA_FOLDER}/`]);

    await events.triggerAsync('saveSettings', state('Meta/Sync data'), state(DEFAULT_PLUGIN_DATA_FOLDER));
    await waitForAllAsyncOperations();
    expect(getFilters()).toEqual(['Meta/Sync data/']);

    settings.pluginDataFolder = 'Other';
    await events.triggerAsync('loadSettings', state('Other'), false);
    await waitForAllAsyncOperations();
    expect(getFilters()).toEqual(['Other/']);

    isSyncEnabled = false;
    for (const callback of storageChangedCallbacks) {
      callback();
    }
    await waitForAllAsyncOperations();
    expect(getFilters()).toEqual([]);

    component.unload();
    expect(storageChangedCallbacks).toEqual([]);
  });

  it('should keep reconciling after a failed run', async () => {
    existingFolders = [DEFAULT_PLUGIN_DATA_FOLDER];
    await app.vault.createFolder(DEFAULT_PLUGIN_DATA_FOLDER);
    vi.spyOn(app.vault.adapter, 'exists').mockRejectedValueOnce(new Error('offline'));

    await expect(component.reconcile()).rejects.toThrow('offline');
    await component.reconcile();

    expect(await app.vault.adapter.read(`${DEFAULT_PLUGIN_DATA_FOLDER}/README.md`)).toBe(PLUGIN_DATA_FOLDER_README);
  });
});
