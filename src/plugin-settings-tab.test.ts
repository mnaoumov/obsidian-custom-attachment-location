import type {
  ButtonComponent,
  DropdownComponent,
  Plugin as ObsidianPlugin,
  TextComponent,
  ToggleComponent
} from 'obsidian';
import type { AsyncEventRef } from 'obsidian-dev-utils/async-events';
import type { DataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import type { PluginEventSource } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';
import type { CodeHighlighterComponent } from 'obsidian-dev-utils/obsidian/setting-components/code-highlighter-component';

import { noopAsync } from 'obsidian-dev-utils/function';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { SettingEx } from 'obsidian-dev-utils/obsidian/setting-ex';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  App,
  ButtonComponent as ButtonComponentClass,
  DropdownComponent as DropdownComponentClass,
  TextComponent as TextComponentClass,
  ToggleComponent as ToggleComponentClass
} from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { Plugin } from './plugin.ts';

import { translationsMap } from './i18n/locales/translations-map.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import { PluginSettingsTab } from './plugin-settings-tab.ts';
import { SAMPLE_CUSTOM_TOKENS } from './plugin-settings.ts';

vi.mock('obsidian-dev-utils/obsidian/modals/confirm', () => ({
  confirm: vi.fn((): Promise<boolean> => Promise.resolve(true))
}));

interface CapturedToggle {
  name: string;
  toggle: ToggleComponent;
}

interface CapturedValueComponent {
  inputEl?: HTMLInputElement | HTMLTextAreaElement;
  name: string;
  setValue(value: string): unknown;
}

interface CreatedTab {
  buttons: ButtonComponentClass[];
  names: string[];
  pluginSettingsComponent: PluginSettingsComponent;
  tab: PluginSettingsTab;
  textLikeComponents: CapturedValueComponent[];
  toggles: CapturedToggle[];
}

class MockDataHandler implements DataHandler {
  public async loadData(): Promise<unknown> {
    await noopAsync();
    return {};
  }

  public async saveData(): Promise<void> {
    await noopAsync();
  }
}

const originalAddButton = SettingEx.prototype.addButton;
const originalAddToggle = SettingEx.prototype.addToggle;
const originalAddText = SettingEx.prototype.addText;
const originalAddCodeHighlighter = SettingEx.prototype.addCodeHighlighter;
const originalAddDropdown = SettingEx.prototype.addDropdown;
const originalSetName = SettingEx.prototype.setName;

async function createTab(): Promise<CreatedTab> {
  const app = App.createConfigured__();
  const originalApp = app.asOriginalType__();
  const plugin = strictProxy<Plugin>({ app: originalApp });
  const pluginSettingsComponent = new PluginSettingsComponent({
    dataHandler: new MockDataHandler(),
    plugin,
    pluginEventSource: strictProxy<PluginEventSource>({
      on: (): AsyncEventRef => strictProxy<AsyncEventRef>({})
    })
  });
  await pluginSettingsComponent.loadWithPromises();

  const obsidianPlugin = strictProxy<ObsidianPlugin>({ app: originalApp });

  const buttons: ButtonComponentClass[] = [];
  const toggles: CapturedToggle[] = [];
  const names: string[] = [];
  const textLikeComponents: CapturedValueComponent[] = [];

  const addTextSpy = vi.spyOn(SettingEx.prototype, 'addText');
  addTextSpy.mockImplementation(function capturingAddText(this: SettingEx, cb: (component: TextComponent) => unknown): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddText.call(this, (component: TextComponent) => {
      textLikeComponents.push({ inputEl: component.inputEl, name, setValue: (value) => component.setValue(value) });
      cb(component);
    });
  });

  const addCodeHighlighterSpy = vi.spyOn(SettingEx.prototype, 'addCodeHighlighter');
  addCodeHighlighterSpy.mockImplementation(function capturingAddCodeHighlighter(this: SettingEx, cb: (component: CodeHighlighterComponent) => void): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddCodeHighlighter.call(this, (component: CodeHighlighterComponent) => {
      textLikeComponents.push({ name, setValue: (value) => component.setValue(value) });
      cb(component);
    });
  });

  const addDropdownSpy = vi.spyOn(SettingEx.prototype, 'addDropdown');
  addDropdownSpy.mockImplementation(function capturingAddDropdown(this: SettingEx, cb: (component: DropdownComponent) => unknown): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddDropdown.call(this, (component: DropdownComponent) => {
      textLikeComponents.push({ name, setValue: (value) => component.setValue(value) });
      cb(component);
    });
  });

  const addButtonSpy = vi.spyOn(SettingEx.prototype, 'addButton');
  addButtonSpy.mockImplementation(function capturingAddButton(this: SettingEx, cb: (button: ButtonComponent) => unknown): SettingEx {
    return originalAddButton.call(this, (button: ButtonComponent) => {
      buttons.push(ButtonComponentClass.fromOriginalType2__(button));
      cb(button);
    });
  });

  const addToggleSpy = vi.spyOn(SettingEx.prototype, 'addToggle');
  addToggleSpy.mockImplementation(function capturingAddToggle(this: SettingEx, cb: (toggle: ToggleComponent) => unknown): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddToggle.call(this, (toggle: ToggleComponent) => {
      toggles.push({ name, toggle });
      cb(toggle);
    });
  });

  const setNameSpy = vi.spyOn(SettingEx.prototype, 'setName');
  setNameSpy.mockImplementation(function capturingSetName(this: SettingEx, name: DocumentFragment | string): SettingEx {
    if (typeof name === 'string') {
      names.push(name);
    }
    return originalSetName.call(this, name);
  });

  const tab = new PluginSettingsTab({
    plugin: obsidianPlugin,
    pluginSettingsComponent
  });

  // eslint-disable-next-line @typescript-eslint/no-deprecated -- PluginSettingsTabBase still relies on the deprecated SettingTab.display() lifecycle method.
  tab.display();
  addButtonSpy.mockRestore();
  addToggleSpy.mockRestore();
  addTextSpy.mockRestore();
  addCodeHighlighterSpy.mockRestore();
  addDropdownSpy.mockRestore();
  setNameSpy.mockRestore();
  return {
    buttons,
    names,
    pluginSettingsComponent,
    tab,
    textLikeComponents,
    toggles
  };
}

async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 20; i++) {
    await noopAsync();
  }
}

beforeAll(async () => {
  await initI18N(translationsMap);
  // Obsidian-dev-utils' bind() probes setPlaceholderValue to detect text-based components.
  for (
    const proto of [
      ToggleComponentClass.prototype,
      DropdownComponentClass.prototype,
      TextComponentClass.prototype,
      ButtonComponentClass.prototype
    ]
  ) {
    if (!('setPlaceholderValue' in proto)) {
      Object.defineProperty(proto, 'setPlaceholderValue', { value: undefined });
    }
  }
});

describe('PluginSettingsTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should be constructable', async () => {
    const { tab } = await createTab();
    expect(tab).toBeInstanceOf(PluginSettingsTab);
  });

  it('should render the expected settings', async () => {
    const { names } = await createTab();
    expect(names).toContain('Location for new attachments');
    expect(names).toContain('Generated attachment file name');
    expect(names).toContain('Duplicate name separator');
    expect(names).toContain('Attachment rename mode');
    expect(names).toContain('Should handle renames');
    expect(names).toContain('Empty folder behavior');
    expect(names).toContain('Special characters');
    expect(names).toContain('Include paths');
    expect(names).toContain('Custom tokens');
    expect(names).toContain('Markdown URL format');
    expect(names).toContain('Timeout in seconds');
  });

  it('should enable debouncing of custom token validation while displayed', async () => {
    const { pluginSettingsComponent } = await createTab();
    expect(pluginSettingsComponent.shouldDebounceCustomTokensValidation).toBe(true);
  });

  it('should disable debouncing of custom token validation when hidden', async () => {
    const { pluginSettingsComponent, tab } = await createTab();
    tab.hide();
    expect(pluginSettingsComponent.shouldDebounceCustomTokensValidation).toBe(false);
  });

  it('should re-render when the should-handle-renames toggle changes', async () => {
    const { tab, toggles } = await createTab();

    const displaySpy = vi.spyOn(tab, 'display');
    const captured = toggles.find((entry) => entry.name === 'Should handle renames');
    expect(captured).toBeDefined();
    captured?.toggle.setValue(false);
    await flushMicrotasks();
    expect(displaySpy).toHaveBeenCalled();
  });

  it('should disable the dependent toggles when renames are not handled', async () => {
    const { pluginSettingsComponent, tab, toggles } = await createTab();
    await pluginSettingsComponent.editAndSave((settings) => {
      settings.shouldHandleRenames = false;
    });
    toggles.length = 0;
    const addToggleSpy = vi.spyOn(SettingEx.prototype, 'addToggle');
    addToggleSpy.mockImplementation(function capturingAddToggle(this: SettingEx, cb: (toggle: ToggleComponent) => unknown): SettingEx {
      const name = this.nameEl.textContent;
      return originalAddToggle.call(this, (toggle: ToggleComponent) => {
        toggles.push({ name, toggle });
        cb(toggle);
      });
    });

    // eslint-disable-next-line @typescript-eslint/no-deprecated -- PluginSettingsTabBase still relies on the deprecated SettingTab.display() lifecycle method.
    tab.display();
    addToggleSpy.mockRestore();
    const folderToggle = toggles.find((entry) => entry.name === 'Should rename attachment folders');
    const fileToggle = toggles.find((entry) => entry.name === 'Should rename attachment files');
    expect(folderToggle?.toggle.disabled).toBe(true);
    expect(fileToggle?.toggle.disabled).toBe(true);
  });

  it('should do nothing when resetting custom tokens that already match the sample', async () => {
    const { buttons, pluginSettingsComponent } = await createTab();
    await pluginSettingsComponent.editAndSave((settings) => {
      settings.customTokensStr = SAMPLE_CUSTOM_TOKENS;
    });
    const button = getResetButton(buttons);
    button.simulateClick__();
    await flushMicrotasks();
    expect(confirm).not.toHaveBeenCalled();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe(SAMPLE_CUSTOM_TOKENS);
  });

  it('should reset custom tokens directly when there is no existing code', async () => {
    const { buttons, pluginSettingsComponent } = await createTab();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe('');
    const button = getResetButton(buttons);
    button.simulateClick__();
    await flushMicrotasks();
    expect(confirm).not.toHaveBeenCalled();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe(SAMPLE_CUSTOM_TOKENS);
  });

  it('should reset custom tokens after confirmation when existing code is present', async () => {
    vi.mocked(confirm).mockResolvedValue(true);
    const { buttons, pluginSettingsComponent } = await createTab();
    await pluginSettingsComponent.editAndSave((settings) => {
      settings.customTokensStr = 'registerCustomToken(\'foo\', () => \'bar\');';
    });
    const button = getResetButton(buttons);
    button.simulateClick__();
    await flushMicrotasks();
    expect(confirm).toHaveBeenCalled();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe(SAMPLE_CUSTOM_TOKENS);
  });

  it('should keep custom tokens when the reset confirmation is cancelled', async () => {
    vi.mocked(confirm).mockResolvedValue(false);
    const { buttons, pluginSettingsComponent } = await createTab();
    const existingCode = 'registerCustomToken(\'foo\', () => \'bar\');';
    await pluginSettingsComponent.editAndSave((settings) => {
      settings.customTokensStr = existingCode;
    });
    const button = getResetButton(buttons);
    button.simulateClick__();
    await flushMicrotasks();
    expect(confirm).toHaveBeenCalled();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe(existingCode);
  });

  it('should normalize and trim the attachment folder path when its value changes', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Location for new attachments');
    component.setValue('assets/folder   ');
    await flushMicrotasks();
    expect(pluginSettingsComponent.settings.attachmentFolderPath).toBe('assets/folder');
  });

  it('should store the duplicate name separator with restored space characters', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Duplicate name separator');
    component.setValue('␣');
    await flushMicrotasks();
    expect(pluginSettingsComponent.settings.duplicateNameSeparator).toBe(' ');
  });

  it('should visualize whitespace as the value is typed into the duplicate name separator', async () => {
    const { textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Duplicate name separator');
    const inputEl = component.inputEl;
    expect(inputEl).toBeDefined();
    if (!inputEl) {
      return;
    }
    inputEl.value = 'a b';
    inputEl.dispatchEvent(new Event('input'));
    expect(inputEl.value).toBe('a␣b');
  });

  it('should convert the selected JPEG quality back to a number', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'JPEG Quality');
    component.setValue('0.50');
    await flushMicrotasks();
    expect(pluginSettingsComponent.settings.jpegQuality).toBe(0.5);
  });

  it('should re-register custom tokens when the custom tokens code changes', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Custom tokens');
    component.setValue('registerCustomToken(\'qux\', () => \'quux\');');
    await flushMicrotasks();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe('registerCustomToken(\'qux\', () => \'quux\');');
  });

  it('should register custom tokens and revalidate after the debounce elapses', async () => {
    vi.useFakeTimers();
    try {
      const { pluginSettingsComponent, textLikeComponents } = await createTab();
      const revalidateSpy = vi.spyOn(pluginSettingsComponent, 'revalidate');
      const component = findComponent(textLikeComponents, 'Custom tokens');
      component.setValue('registerCustomToken(\'corge\', () => \'grault\');');
      await vi.advanceTimersByTimeAsync(2000);
      expect(revalidateSpy).toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('should default the caret offsets to zero when the input reports no selection', async () => {
    const { textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Duplicate name separator');
    const inputEl = component.inputEl;
    expect(inputEl).toBeDefined();
    if (!inputEl) {
      return;
    }
    Object.defineProperty(inputEl, 'selectionStart', { configurable: true, value: null });
    Object.defineProperty(inputEl, 'selectionEnd', { configurable: true, value: null });
    inputEl.value = 'c d';
    inputEl.dispatchEvent(new Event('input'));
    expect(inputEl.value).toBe('c␣d');
  });
});

function findComponent(components: CapturedValueComponent[], name: string): CapturedValueComponent {
  const component = components.find((entry) => entry.name === name);
  if (!component) {
    throw new Error(`Component "${name}" was not captured.`);
  }
  return component;
}

function getResetButton(buttons: ButtonComponentClass[]): ButtonComponentClass {
  const button = buttons[0];
  if (!button) {
    throw new Error('Reset button was not captured.');
  }
  return button;
}
