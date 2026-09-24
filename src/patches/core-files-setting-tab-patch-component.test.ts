import type {
  App as AppOriginal,
  ButtonComponent as ButtonComponentOriginal,
  SettingDefinitionItem,
  SettingDefinitionRender,
  SettingTab
} from 'obsidian';

import { AsyncEvents } from 'obsidian-dev-utils/async-events';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { ButtonComponent } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { PluginSettings } from '../plugin-settings.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { CoreFilesSettingTabPatchComponent } from './core-files-setting-tab-patch-component.ts';

interface CoreFilesSettingTabDouble {
  getSettingDefinitions: () => SettingDefinitionItem[];
  readonly id: string;
  update: ReturnType<typeof vi.fn<() => void>>;
}

interface SettingsState {
  readonly effectiveValues: Pick<PluginSettings, 'shouldFollowObsidianAttachmentLocation'>;
}

// Obsidian's own id for the core Files and links settings tab.
const CORE_FILES_SETTING_TAB_ID = 'file';
const PLUGIN_ID = 'obsidian-custom-attachment-location';

// Stand-ins for Obsidian's own rows. The render sources mention the config key exactly as Obsidian's do.
const unrelatedBefore: SettingDefinitionItem = { control: { key: 'focusNewTab', type: 'toggle' }, name: 'Always focus new tabs' };
const locationDropdown: SettingDefinitionRender = {
  desc: 'Where newly added attachments are placed.',
  name: 'Default location for new attachments',
  render: (): void => {
    castTo<AppOriginal>(null).vault.setConfig('attachmentFolderPath', '/');
  }
};
const folderText: SettingDefinitionRender = {
  name: 'Attachment folder path',
  render: (): void => {
    castTo<AppOriginal>(null).vault.setConfig('attachmentFolderPath', 'assets');
  }
};
const subfolderText: SettingDefinitionRender = {
  name: 'Subfolder name',
  render: (): void => {
    castTo<AppOriginal>(null).vault.setConfig('attachmentFolderPath', './attachments');
  }
};
const unrelatedRender: SettingDefinitionRender = {
  name: 'New link format',
  render: (): void => {
    castTo<AppOriginal>(null).vault.setConfig('newLinkFormat', 'shortest');
  }
};

let events: AsyncEvents;
let settings: Pick<PluginSettings, 'shouldFollowObsidianAttachmentLocation'>;
let openTabById: ReturnType<typeof vi.fn<(id: string) => void>>;
let definitions: SettingDefinitionItem[];
let tab: CoreFilesSettingTabDouble;
let settingTabs: object[];
let component: CoreFilesSettingTabPatchComponent;

beforeAll(async () => {
  await initI18N(translationsMap);
});

beforeEach(() => {
  events = new AsyncEvents();
  settings = { shouldFollowObsidianAttachmentLocation: false };
  openTabById = vi.fn<(id: string) => void>();
  definitions = [unrelatedBefore, locationDropdown, folderText, subfolderText, unrelatedRender];
  tab = {
    getSettingDefinitions: (): SettingDefinitionItem[] => definitions,
    id: CORE_FILES_SETTING_TAB_ID,
    update: vi.fn<() => void>()
  };
  settingTabs = [{ id: 'editor' }, tab];
  const app = strictProxy<AppOriginal>({
    setting: strictProxy<AppOriginal['setting']>({
      openTabById: castTo<AppOriginal['setting']['openTabById']>(openTabById),
      settingTabs: castTo<SettingTab[]>(settingTabs)
    })
  });
  const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
    on: castTo<PluginSettingsComponent['on']>(events.on.bind(events)),
    settings: castTo<PluginSettings>(settings)
  });
  component = new CoreFilesSettingTabPatchComponent({ app, pluginId: PLUGIN_ID, pluginSettingsComponent });
});

afterEach(() => {
  component.unload();
  vi.restoreAllMocks();
});

function state(shouldFollowObsidianAttachmentLocation: boolean): SettingsState {
  return { effectiveValues: { shouldFollowObsidianAttachmentLocation } };
}

describe('CoreFilesSettingTabPatchComponent', () => {
  it('should replace the attachment-location rows with one row naming the plugin', () => {
    component.load();

    const result = tab.getSettingDefinitions();

    expect(result).toHaveLength(3);
    expect(result[0]).toBe(unrelatedBefore);
    expect(result[2]).toBe(unrelatedRender);
    const controlledRow = castTo<SettingDefinitionRender>(result[1]);
    expect(controlledRow.name).toBe('Default location for new attachments');
    expect(controlledRow.desc).toContain('Controlled by Custom Attachment Location');
  });

  it('should open the plugin\'s own settings from the replacement row', () => {
    component.load();
    const controlledRow = castTo<SettingDefinitionRender>(tab.getSettingDefinitions()[1]);
    const button = ButtonComponent.create__(createDiv());
    type RenderSetting = Parameters<SettingDefinitionRender['render']>[0];
    const setting: RenderSetting = strictProxy<RenderSetting>({
      addButton(callback: (component: ButtonComponentOriginal) => unknown): RenderSetting {
        callback(button.asOriginalType2__());
        return setting;
      }
    });

    controlledRow.render(setting, castTo<Parameters<SettingDefinitionRender['render']>[1]>(null));
    button.simulateClick__();

    expect(openTabById).toHaveBeenCalledWith(PLUGIN_ID);
  });

  it('should leave the definitions untouched while the plugin follows Obsidian', () => {
    settings.shouldFollowObsidianAttachmentLocation = true;
    component.load();

    expect(tab.getSettingDefinitions()).toBe(definitions);
  });

  it('should leave the definitions untouched when no row writes the attachment folder path', () => {
    definitions = [unrelatedBefore, unrelatedRender];
    component.load();

    expect(tab.getSettingDefinitions()).toBe(definitions);
  });

  it('should hand the definitions back untouched when the rewrite throws', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    function hostileRender(): void {
      // A row whose source cannot even be read.
    }
    hostileRender.toString = (): string => {
      throw new Error('boom');
    };
    definitions = [{ name: 'Hostile', render: hostileRender }];
    component.load();

    expect(tab.getSettingDefinitions()).toBe(definitions);
    expect(warn).toHaveBeenCalled();
  });

  it('should do nothing when Obsidian has no Files and links tab', () => {
    settingTabs.splice(settingTabs.indexOf(tab), 1);
    component.load();

    expect(tab.getSettingDefinitions()).toBe(definitions);
    expect(tab.update).not.toHaveBeenCalled();
  });

  it('should do nothing when the tab predates the declarative settings API', () => {
    const legacyTab = { id: CORE_FILES_SETTING_TAB_ID };
    settingTabs[settingTabs.indexOf(tab)] = legacyTab;
    component.load();

    expect(Object.keys(legacyTab)).toEqual(['id']);
  });

  it('should refresh the tab on load, and again with the original rows on unload', () => {
    component.load();
    expect(tab.update).toHaveBeenCalledTimes(1);

    let definitionsSeenOnUnload: null | SettingDefinitionItem[] = null;
    tab.update.mockImplementation(() => {
      definitionsSeenOnUnload = tab.getSettingDefinitions();
    });
    component.unload();

    expect(tab.update).toHaveBeenCalledTimes(2);
    expect(definitionsSeenOnUnload).toBe(definitions);
    expect(tab.getSettingDefinitions()).toBe(definitions);
  });

  it('should refresh the tab when the mode is switched, and only then', async () => {
    component.load();
    tab.update.mockClear();

    await events.triggerAsync('saveSettings', state(false), state(false));
    expect(tab.update).not.toHaveBeenCalled();

    await events.triggerAsync('saveSettings', state(true), state(false));
    expect(tab.update).toHaveBeenCalledTimes(1);
  });

  it('should refresh the tab when the settings are reloaded from disk', async () => {
    component.load();
    tab.update.mockClear();

    await events.triggerAsync('loadSettings', state(true), false);

    expect(tab.update).toHaveBeenCalledTimes(1);
  });

  it('should survive a tab whose refresh throws', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    tab.update.mockImplementation(() => {
      throw new Error('boom');
    });

    expect(() => {
      component.load();
    }).not.toThrow();
    expect(warn).toHaveBeenCalled();
  });
});
