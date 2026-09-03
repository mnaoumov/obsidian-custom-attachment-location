import type { App as AppOriginal } from 'obsidian';
import type { PluginApiRef } from 'obsidian-dev-utils/obsidian/plugin/plugin-api';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/vault';
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
  HandedOverSettings
} from './advanced-rename-and-delete-handler.ts';

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
import {
  ADVANCED_RENAME_AND_DELETE_HANDLER_READ_BACK_API_CONTRACT,
  DEFAULT_HANDED_OVER_SETTINGS
} from './advanced-rename-and-delete-handler.ts';
// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import { HandedOverSettingsComponent } from './handed-over-settings-component.ts';

const PROVIDER_SETTINGS: HandedOverSettings = {
  emptyFolderBehavior: EmptyFolderBehavior.Keep,
  notePriorities: ['.md'],
  shouldRenameAttachmentFiles: true,
  treatAsAttachmentExtensions: ['.drawing.md']
};

let app: AppOriginal;
let isPathIgnored: ReturnType<typeof vi.fn<(path: string) => boolean>>;
let isTreatedAsAttachment: ReturnType<typeof vi.fn<(path: string) => boolean>>;
let watchedApi: AdvancedRenameAndDeleteHandlerApi | null;

beforeEach(() => {
  vi.clearAllMocks();
  app = App.createConfigured__().asOriginalType__();
  isPathIgnored = vi.fn((_path: string): boolean => true);
  isTreatedAsAttachment = vi.fn((_path: string): boolean => true);
  watchedApi = castTo<AdvancedRenameAndDeleteHandlerApi>({
    getSettings: () => PROVIDER_SETTINGS,
    isPathIgnored,
    isTreatedAsAttachment
  });
  mockWatchPluginApi.mockImplementation(() =>
    castTo<PluginApiRef<AdvancedRenameAndDeleteHandlerApi>>({
      get value(): AdvancedRenameAndDeleteHandlerApi | null {
        return watchedApi;
      }
    })
  );
});

describe('HandedOverSettingsComponent', () => {
  it('should watch the provider under the ^1 contract', () => {
    createComponent().load();

    expect(mockWatchPluginApi).toHaveBeenCalledWith(expect.objectContaining({
      apiVersionRange: '^1',
      pluginId: 'advanced-rename-and-delete-handler'
    }));
  });

  /*
   * The consumer's own contract wins over the provider's, and here that is load-bearing rather than
   * decorative. Advanced Rename and Delete Handler 1.1.1 publishes contract 1.0.0, which declares only
   * `migrateSettings` — so it satisfies `^1`, and a shape check made against the PROVIDER's contract would
   * pass and hand over an API with no `getSettings` for every read to throw on. Demanding the three
   * read-back members is what makes that record fail the check and leaves the fallback in charge instead.
   */
  it('should demand the read-back members, so a provider that publishes only migrateSettings is refused', () => {
    createComponent().load();

    expect(mockWatchPluginApi).toHaveBeenCalledWith(expect.objectContaining({
      contract: ADVANCED_RENAME_AND_DELETE_HANDLER_READ_BACK_API_CONTRACT
    }));
    expect(Object.keys(ADVANCED_RENAME_AND_DELETE_HANDLER_READ_BACK_API_CONTRACT)).toStrictEqual([
      'getSettings',
      'isPathIgnored',
      'isTreatedAsAttachment'
    ]);
    expect(ADVANCED_RENAME_AND_DELETE_HANDLER_READ_BACK_API_CONTRACT).not.toHaveProperty('migrateSettings');
  });

  describe('while the provider is available', () => {
    it('should read the settings back from it', () => {
      const component = createComponent();
      component.load();

      expect(component.settings).toStrictEqual(PROVIDER_SETTINGS);
    });

    it('should delegate isPathIgnored to it', () => {
      const component = createComponent();
      component.load();

      expect(component.isPathIgnored('ignored/note.md')).toBe(true);
      expect(isPathIgnored).toHaveBeenCalledWith('ignored/note.md');
    });

    it('should delegate isTreatedAsAttachment to it', () => {
      const component = createComponent();
      component.load();

      expect(component.isTreatedAsAttachment('drawing.excalidraw.md')).toBe(true);
      expect(isTreatedAsAttachment).toHaveBeenCalledWith('drawing.excalidraw.md');
    });

    // Uncached on purpose: the user can edit these in the other plugin's tab at any time, and asking on
    // Every call means there is no staleness to invalidate.
    it('should reflect a later change without needing to be told', () => {
      const component = createComponent();
      component.load();
      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.Keep);

      watchedApi = castTo<AdvancedRenameAndDeleteHandlerApi>({
        getSettings: () => ({ ...PROVIDER_SETTINGS, emptyFolderBehavior: EmptyFolderBehavior.Delete })
      });

      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.Delete);
    });
  });

  // A user who declines the suggestion is a supported state, so every read has to answer without the
  // Provider — and answer with THIS plugin's historic defaults, not the other plugin's.
  describe('while the provider is unavailable', () => {
    beforeEach(() => {
      watchedApi = null;
    });

    it('should fall back to this plugin\'s own defaults', () => {
      const component = createComponent();
      component.load();

      expect(component.settings).toBe(DEFAULT_HANDED_OVER_SETTINGS);
      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.DeleteWithEmptyParents);
    });

    it('should ignore no path, because nothing is configured to exclude', () => {
      const component = createComponent();
      component.load();

      expect(component.isPathIgnored('anything.md')).toBe(false);
    });

    it('should still treat the default extensions as attachments', () => {
      const component = createComponent();
      component.load();

      expect(component.isTreatedAsAttachment('drawing.excalidraw.md')).toBe(true);
      expect(component.isTreatedAsAttachment('note.md')).toBe(false);
    });
  });

  // Before `onload` there is no ref at all, and the base may read through the component while children are
  // Still being wired up.
  it('should answer from the defaults before it has loaded', () => {
    const component = createComponent();

    expect(component.settings).toBe(DEFAULT_HANDED_OVER_SETTINGS);
    expect(component.isPathIgnored('anything.md')).toBe(false);
    expect(component.isTreatedAsAttachment('drawing.excalidraw.md')).toBe(true);
  });
});

function createComponent(): HandedOverSettingsComponent {
  return new HandedOverSettingsComponent({ app });
}
