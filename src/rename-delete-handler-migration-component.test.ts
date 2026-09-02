import type { App as AppOriginal } from 'obsidian';
import type { PluginApiRef } from 'obsidian-dev-utils/obsidian/plugin/plugin-api';

import { noopAsync } from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type {
  AdvancedRenameAndDeleteHandlerApi,
  MigrateSettingsParams,
  MigrateSettingsResult
} from './advanced-rename-and-delete-handler.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

// `watchPluginApi` is a function export, so it cannot be spied on in place — the module is mocked instead,
// Keeping every other export real.
const { mockWatchPluginApi } = vi.hoisted(() => ({
  mockWatchPluginApi: vi.fn<() => PluginApiRef<AdvancedRenameAndDeleteHandlerApi>>()
}));

vi.mock('obsidian-dev-utils/obsidian/plugin/plugin-api', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/plugin/plugin-api')>(),
  watchPluginApi: mockWatchPluginApi
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import { ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT } from './advanced-rename-and-delete-handler.ts';
// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import { PluginSettings } from './plugin-settings.ts';
// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import { RenameDeleteHandlerMigrationComponent } from './rename-delete-handler-migration-component.ts';

const SOURCE_PLUGIN_ID = 'obsidian-custom-attachment-location';

let app: AppOriginal;
let changeListeners: (() => void)[];
let editAndSave: ReturnType<typeof vi.fn<(settingsEditor: (settings: PluginSettings) => void) => Promise<void>>>;
let loadSettingsListeners: (() => void)[];
let migrateSettings: ReturnType<typeof vi.fn<(params: MigrateSettingsParams) => Promise<MigrateSettingsResult>>>;
let settings: PluginSettings;
let watchedApi: AdvancedRenameAndDeleteHandlerApi | null;

beforeEach(() => {
  vi.clearAllMocks();
  app = App.createConfigured__().asOriginalType__();
  changeListeners = [];
  loadSettingsListeners = [];
  settings = new PluginSettings();
  migrateSettings = vi.fn(() => Promise.resolve({ isApplied: true }));
  editAndSave = vi.fn((settingsEditor: (currentSettings: PluginSettings) => void) => {
    settingsEditor(settings);
    return noopAsync();
  });
  watchedApi = castTo<AdvancedRenameAndDeleteHandlerApi>({ migrateSettings });
  mockWatchPluginApi.mockImplementation(() =>
    castTo<PluginApiRef<AdvancedRenameAndDeleteHandlerApi>>({
      off: (_name: string, callback: () => void) => {
        changeListeners.remove(callback);
      },
      on: (_name: string, callback: () => void) => {
        changeListeners.push(callback);
      },
      get value(): AdvancedRenameAndDeleteHandlerApi | null {
        return watchedApi;
      }
    })
  );
});

describe('RenameDeleteHandlerMigrationComponent', () => {
  it('should watch the provider under the ^1 contract', () => {
    createComponent().load();

    expect(mockWatchPluginApi).toHaveBeenCalledWith(expect.objectContaining({
      apiVersionRange: '^1',
      pluginId: 'advanced-rename-and-delete-handler'
    }));
  });

  /*
   * Deliberately narrower than the read-back's contract. `migrateSettings` has been published since
   * contract 1.0.0, so demanding the 1.1.0 read-back members here would refuse to offer the migration to a
   * user on an older provider — precisely the user who still has settings worth migrating.
   */
  it('should demand only migrateSettings, so an older provider can still be migrated to', () => {
    createComponent().load();

    expect(mockWatchPluginApi).toHaveBeenCalledWith(expect.objectContaining({
      contract: ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT
    }));
    expect(Object.keys(ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT)).toStrictEqual(['migrateSettings']);
  });

  // The regression the live run of [[T711-P18]] caught. The settings component is a sibling whose own load is
  // Still in flight while this one loads, so its `settings` still hold the defaults. Gating the watch on the
  // Pending value at that moment saw `null` on a vault that had one, registered nothing, and lost the
  // Migration for good.
  it('should still watch the provider when the settings have not been read yet', () => {
    settings.proposedRenameDeleteSettings = null;

    createComponent().load();

    expect(mockWatchPluginApi).toHaveBeenCalled();
    expect(changeListeners).toHaveLength(1);
  });

  it('should offer the migration once the settings arrive carrying pending values', async () => {
    settings.proposedRenameDeleteSettings = null;
    createComponent().load();
    expect(migrateSettings).not.toHaveBeenCalled();

    settings.proposedRenameDeleteSettings = { shouldHandleRenames: false };
    for (const listener of loadSettingsListeners) {
      listener();
    }

    await vi.waitFor(() => {
      expect(migrateSettings).toHaveBeenCalledWith({
        proposedSettings: { shouldHandleRenames: false },
        sourcePluginId: SOURCE_PLUGIN_ID
      });
    });
  });

  it('should offer every pending value to the provider', async () => {
    settings.proposedRenameDeleteSettings = {
      excludePaths: ['ignored'],
      notePriorities: ['.md'],
      shouldHandleDeletions: true,
      shouldHandleRenames: false
    };

    createComponent().load();
    await vi.waitFor(() => {
      expect(migrateSettings).toHaveBeenCalledWith({
        proposedSettings: {
          excludePaths: ['ignored'],
          notePriorities: ['.md'],
          shouldHandleDeletions: true,
          shouldHandleRenames: false
        },
        sourcePluginId: SOURCE_PLUGIN_ID
      });
    });
  });

  // Also a regression the live run caught: `setProperty` edits only the in-memory state, so the retirement
  // Was forgotten on the next reload and the migration was offered again forever.
  it('should retire the pending values to disk once the user applies the migration', async () => {
    settings.proposedRenameDeleteSettings = { shouldHandleRenames: false };

    createComponent().load();
    await vi.waitFor(() => {
      expect(editAndSave).toHaveBeenCalled();
    });
    expect(settings.proposedRenameDeleteSettings).toBeNull();
  });

  it('should keep the values pending when the user cancels', async () => {
    settings.proposedRenameDeleteSettings = { shouldHandleRenames: false };
    migrateSettings.mockResolvedValue({ isApplied: false });

    createComponent().load();
    await vi.waitFor(() => {
      expect(migrateSettings).toHaveBeenCalled();
    });
    expect(editAndSave).not.toHaveBeenCalled();
    expect(settings.proposedRenameDeleteSettings).toStrictEqual({ shouldHandleRenames: false });
  });

  it('should stay quiet while the provider is unavailable', async () => {
    settings.proposedRenameDeleteSettings = { shouldHandleRenames: true };
    watchedApi = null;

    createComponent().load();
    await noopAsync();

    expect(migrateSettings).not.toHaveBeenCalled();
  });

  it('should offer the migration as soon as the provider appears', async () => {
    settings.proposedRenameDeleteSettings = { shouldHandleRenames: true };
    watchedApi = null;
    createComponent().load();

    watchedApi = castTo<AdvancedRenameAndDeleteHandlerApi>({ migrateSettings });
    for (const listener of changeListeners) {
      listener();
    }

    await vi.waitFor(() => {
      expect(migrateSettings).toHaveBeenCalledOnce();
    });
  });

  it('should not open a second dialog while one is already open', async () => {
    settings.proposedRenameDeleteSettings = { shouldHandleRenames: true };
    let resolveMigration: (() => void) | null = null;
    migrateSettings.mockImplementation(() =>
      new Promise((resolve) => {
        resolveMigration = (): void => {
          resolve({ isApplied: true });
        };
      })
    );

    createComponent().load();
    await vi.waitFor(() => {
      expect(migrateSettings).toHaveBeenCalledOnce();
    });
    for (const listener of changeListeners) {
      listener();
    }
    await noopAsync();

    expect(migrateSettings).toHaveBeenCalledOnce();
    castTo<() => void>(resolveMigration)();
  });

  it('should drop its change listener when it unloads', () => {
    settings.proposedRenameDeleteSettings = { shouldHandleRenames: true };
    const component = createComponent();

    component.load();
    expect(changeListeners).toHaveLength(1);
    component.unload();
    expect(changeListeners).toHaveLength(0);
  });
});

function createComponent(): RenameDeleteHandlerMigrationComponent {
  return new RenameDeleteHandlerMigrationComponent({
    app,
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
      editAndSave,
      on: castTo<PluginSettingsComponent['on']>(vi.fn((_name: string, callback: () => void) => {
        loadSettingsListeners.push(callback);
        return { asyncEventSource: { offref: vi.fn() } };
      })),
      get settings(): PluginSettings {
        return settings;
      }
    }),
    sourcePluginId: SOURCE_PLUGIN_ID
  });
}
