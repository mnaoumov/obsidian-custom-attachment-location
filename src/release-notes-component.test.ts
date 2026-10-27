import type { ReleaseNotesComponent } from '@mnaoumov/obsidian-lib/components/release-notes-component';
import type { App as AppOriginal } from 'obsidian';

import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { alert } from '@mnaoumov/obsidian-lib/modals/alert';
import { noopAsync } from '@mnaoumov/typescript-lib/function';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
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

import type { PluginSettingsComponent } from './settings/plugin-settings-component.ts';
import type { PluginSettings } from './settings/plugin-settings.ts';

import { translationsMap } from './i18n/locales/translations-map.ts';
import { createReleaseNotesComponent } from './release-notes-component.ts';

interface LayoutReadyTrigger {
  setLayoutReady__: () => void;
}

interface TestContext {
  readonly app: AppOriginal;
  readonly editAndSave: ReturnType<typeof vi.fn>;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly settings: PluginSettings;
}

vi.mock('@mnaoumov/obsidian-lib/modals/alert', () => ({
  alert: vi.fn(() => noopAsync())
}));

const mockAlert = vi.mocked(alert);

const PLUGIN_NAME = 'Custom Attachment Location';
const PLUGIN_VERSION = '14.0.0';

let context: TestContext;
const loadedComponents: ReleaseNotesComponent[] = [];

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('createReleaseNotesComponent', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();

    const settings = strictProxy<PluginSettings>({ version: '' });
    const editAndSave = vi.fn((editor: (settings: PluginSettings) => void): Promise<void> => {
      editor(settings);
      return noopAsync();
    });
    const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      editAndSave,
      settings,
      whenLoadedFromFile: vi.fn((): Promise<void> => noopAsync())
    });

    context = {
      app: App.createConfigured__().asOriginalType__(),
      editAndSave,
      pluginSettingsComponent,
      settings
    };
  });

  afterEach(() => {
    for (const component of loadedComponents) {
      component.unload();
    }
    loadedComponents.length = 0;
    vi.useRealTimers();
  });

  it('should show nothing on a fresh install, and record the current version', async () => {
    await startWithStoredVersion('');

    expect(mockAlert).not.toHaveBeenCalled();
    expect(context.settings.version).toBe(PLUGIN_VERSION);
  });

  it('should show nothing when every note is older than the stored version, and still record the current version', async () => {
    await startWithStoredVersion('13.0.0');

    expect(mockAlert).not.toHaveBeenCalled();
    expect(context.settings.version).toBe(PLUGIN_VERSION);
  });

  it('should show only the notes newer than the stored version, under a title naming the plugin', async () => {
    await startWithStoredVersion('9.2.0');

    expect(mockAlert).toHaveBeenCalledOnce();
    const params = mockAlert.mock.lastCall?.[0];
    const title = castTo<DocumentFragment>(params?.title);
    expect(title.textContent).toBe('Custom Attachment Location release notes');
    // The library renders the plugin name as code.
    expect(title.querySelector('code')?.textContent).toBe('Custom Attachment Location');
    const headings = Array.from(castTo<DocumentFragment>(params?.message).querySelectorAll('h3'), (heading) => heading.textContent);
    expect(headings).toEqual(['9.16.0', '10.0.0', '11.0.0']);
    expect(context.settings.version).toBe(PLUGIN_VERSION);
  });

  it('should warn about a stored version newer than the plugin, show no notes, and leave the stored version alone', async () => {
    await startWithStoredVersion('99.0.0');

    expect(mockAlert).toHaveBeenCalledOnce();
    const params = mockAlert.mock.lastCall?.[0];
    expect(params?.title).toBe('Custom Attachment Location version mismatch');
    const message = castTo<DocumentFragment>(params?.message);
    expect(message.textContent).toContain('plugins/custom-attachment-location/data.json');
    expect(message.textContent).toContain('99.0.0');
    expect(message.querySelectorAll('h3')).toHaveLength(0);
    expect(context.editAndSave).not.toHaveBeenCalled();
    expect(context.settings.version).toBe('99.0.0');
  });
});

async function startWithStoredVersion(storedVersion: string): Promise<void> {
  context.settings.version = storedVersion;
  const component = createReleaseNotesComponent({
    app: context.app,
    pluginDirectory: 'plugins/custom-attachment-location',
    pluginName: PLUGIN_NAME,
    pluginSettingsComponent: context.pluginSettingsComponent,
    pluginVersion: PLUGIN_VERSION
  });
  loadedComponents.push(component);
  component.load();
  castTo<LayoutReadyTrigger>(context.app.workspace).setLayoutReady__();
  await vi.runAllTimersAsync();
}
