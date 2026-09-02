import type { PrismModule } from '@obsidian-typings/obsidian-public-latest/implementations';
import type {
  ButtonComponent,
  DropdownComponent,
  SettingDefinition,
  SettingDefinitionGroup,
  SettingDefinitionItem,
  SettingDefinitionPage,
  SettingDefinitionRender,
  SettingGroup,
  ToggleComponent
} from 'obsidian';
import type { AsyncEventRef } from 'obsidian-dev-utils/async-events';
import type { PluginSuggestionComponent } from 'obsidian-dev-utils/obsidian/components/plugin-suggestion-component';
import type { DataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import type { PluginEventSource } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';
import type { CodeHighlighterComponent } from 'obsidian-dev-utils/obsidian/setting-components/code-highlighter-component';
import type { MultipleTextComponent } from 'obsidian-dev-utils/obsidian/setting-components/multiple-text-component';
import type { NumberComponent } from 'obsidian-dev-utils/obsidian/setting-components/number-component';

import { waitForAllAsyncOperations } from 'obsidian-dev-utils/async';
import { noopAsync } from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { SuggestedPluginState } from 'obsidian-dev-utils/obsidian/components/plugin-suggestion-component';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { SettingEx } from 'obsidian-dev-utils/obsidian/setting-ex';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { ValueWrapper } from 'obsidian-dev-utils/value-wrapper';
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

import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';
import type { Plugin } from './plugin.ts';

import { translationsMap } from './i18n/locales/translations-map.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import { PluginSettingsTab } from './plugin-settings-tab.ts';
import {
  AttachmentRenameMode,
  ConvertImagesToJpegMode,
  SAMPLE_CUSTOM_TOKENS
} from './plugin-settings.ts';
import { TokenValidator } from './token-validator.ts';

vi.mock('obsidian-dev-utils/obsidian/modals/confirm', () => ({
  confirm: vi.fn((): Promise<boolean> => Promise.resolve(true))
}));

// The obsidian-test-mocks package does not model Obsidian's loadPrism, so return a stub prism; otherwise the real CodeHighlighterComponent's highlight-on-setValue (new in dev-utils 86.0.0) rejects.
vi.mock('@obsidian-typings/obsidian-public-latest/implementations', async (importOriginal) => {
  const original = await importOriginal<typeof import('@obsidian-typings/obsidian-public-latest/implementations')>();
  return {
    ...original,
    loadPrism: vi.fn((): Promise<PrismModule> => Promise.resolve(strictProxy<PrismModule>({ highlightElement: vi.fn() })))
  };
});

// This test renders the whole settings tab and drains the debounced revalidation under fake timers.
// Under coverage instrumentation that work exceeds the default 5-second test timeout.
const DEBOUNCE_REVALIDATION_TEST_TIMEOUT_IN_MILLISECONDS = 30_000;

// Every declared row across the inline Core group and the eight sub-pages, guarding against a whole section being dropped when rows are moved between pages.
// 28 = 27 setting rows + the suggestion banner row that rides at the top.
const EXPECTED_ROW_COUNT = 28;

// The suggestion banner's two inputs, so a test can drive both the row's render and its visibility.
const renderBannerMock = vi.fn<(containerEl: HTMLElement) => void>();
let suggestedPluginState = SuggestedPluginState.Enabled;

interface CapturedMultipleTextComponent {
  name: string;
  setValue(value: readonly string[]): unknown;
}

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
  multipleTextComponents: CapturedMultipleTextComponent[];
  names: string[];
  pluginSettingsComponent: PluginSettingsComponent;
  tab: PluginSettingsTab;
  textLikeComponents: CapturedValueComponent[];
  toggles: CapturedToggle[];
}

interface DeclaredRow {
  disabled?: (() => boolean) | boolean;
  visible?: (() => boolean) | boolean;
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
const originalAddNumber = SettingEx.prototype.addNumber;
const originalAddMultipleText = SettingEx.prototype.addMultipleText;
const originalSetName = SettingEx.prototype.setName;

/**
 * Resolves a declarative predicate that may be a boolean, a function, or absent.
 *
 * @param predicate - The predicate.
 * @param shouldDefaultTo - The value to use when the predicate is absent.
 * @returns The resolved value.
 */
function checkPredicate(predicate: (() => boolean) | boolean | undefined, shouldDefaultTo: boolean): boolean {
  if (typeof predicate === 'function') {
    return predicate();
  }

  return predicate ?? shouldDefaultTo;
}

async function createTab(configure?: (settings: PluginSettings) => void): Promise<CreatedTab> {
  const app = App.createConfigured__();
  const originalApp = app.asOriginalType__();
  const validatorWrapper = ValueWrapper.unset<TokenValidator>();
  const pluginSettingsComponent = new PluginSettingsComponent({
    app: originalApp,
    dataHandler: new MockDataHandler(),
    handedOverSettingsComponent: strictProxy<HandedOverSettingsComponent>({
      isTreatedAsAttachment: (path) => path.endsWith('.excalidraw.md')
    }),
    pluginEventSource: strictProxy<PluginEventSource>({
      on: (): AsyncEventRef => strictProxy<AsyncEventRef>({})
    }),
    validatorWrapper
  });
  validatorWrapper.value = new TokenValidator({
    app: originalApp,
    pluginSettingsComponent
  });
  await pluginSettingsComponent.loadWithPromises();

  const obsidianPlugin = strictProxy<Plugin>({ app: originalApp });

  const buttons: ButtonComponentClass[] = [];
  const toggles: CapturedToggle[] = [];
  const names: string[] = [];
  const textLikeComponents: CapturedValueComponent[] = [];
  const multipleTextComponents: CapturedMultipleTextComponent[] = [];

  const addTextSpy = vi.spyOn(SettingEx.prototype, 'addText');
  addTextSpy.mockImplementation(function capturingAddText(this: SettingEx, callback): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddText.call(this, (component) => {
      textLikeComponents.push({ inputEl: component.inputEl, name, setValue: (value) => component.setValue(value) });
      callback(component);
    });
  });

  const addCodeHighlighterSpy = vi.spyOn(SettingEx.prototype, 'addCodeHighlighter');
  addCodeHighlighterSpy.mockImplementation(function capturingAddCodeHighlighter(this: SettingEx, callback): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddCodeHighlighter.call(this, (component: CodeHighlighterComponent) => {
      textLikeComponents.push({ name, setValue: (value) => component.setValue(value) });
      callback(component);
    });
  });

  const addDropdownSpy = vi.spyOn(SettingEx.prototype, 'addDropdown');
  addDropdownSpy.mockImplementation(function capturingAddDropdown(this: SettingEx, callback): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddDropdown.call(this, (component: DropdownComponent) => {
      textLikeComponents.push({ name, setValue: (value) => component.setValue(value) });
      callback(component);
    });
  });

  const addNumberSpy = vi.spyOn(SettingEx.prototype, 'addNumber');
  addNumberSpy.mockImplementation(function capturingAddNumber(this: SettingEx, callback): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddNumber.call(this, (component: NumberComponent) => {
      textLikeComponents.push({ inputEl: component.inputEl, name, setValue: (value) => component.setValue(Number(value)) });
      callback(component);
    });
  });

  const addMultipleTextSpy = vi.spyOn(SettingEx.prototype, 'addMultipleText');
  addMultipleTextSpy.mockImplementation(function capturingAddMultipleText(this: SettingEx, callback): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddMultipleText.call(this, (component: MultipleTextComponent) => {
      multipleTextComponents.push({ name, setValue: (value) => component.setValue(value) });
      callback(component);
    });
  });

  const addButtonSpy = vi.spyOn(SettingEx.prototype, 'addButton');
  addButtonSpy.mockImplementation(function capturingAddButton(this: SettingEx, callback): SettingEx {
    return originalAddButton.call(this, (button: ButtonComponent) => {
      buttons.push(ButtonComponentClass.fromOriginalType2__(button));
      callback(button);
    });
  });

  const addToggleSpy = vi.spyOn(SettingEx.prototype, 'addToggle');
  addToggleSpy.mockImplementation(function capturingAddToggle(this: SettingEx, callback): SettingEx {
    const name = this.nameEl.textContent;
    return originalAddToggle.call(this, (toggle: ToggleComponent) => {
      toggles.push({ name, toggle });
      callback(toggle);
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
    pluginSettingsComponent,
    pluginSuggestionComponent: strictProxy<PluginSuggestionComponent>({
      getSuggestedPluginState: () => suggestedPluginState,
      renderBanner: renderBannerMock
    })
  });

  if (configure) {
    await pluginSettingsComponent.editAndSave(configure);
  }

  renderRows(tab);
  addButtonSpy.mockRestore();
  addToggleSpy.mockRestore();
  addTextSpy.mockRestore();
  addCodeHighlighterSpy.mockRestore();
  addDropdownSpy.mockRestore();
  addNumberSpy.mockRestore();
  addMultipleTextSpy.mockRestore();
  setNameSpy.mockRestore();
  return {
    buttons,
    multipleTextComponents,
    names,
    pluginSettingsComponent,
    tab,
    textLikeComponents,
    toggles
  };
}

/**
 * Finds a declared row by name.
 *
 * @param tab - The settings tab.
 * @param name - The row name.
 * @returns The row.
 */
function findRow(tab: PluginSettingsTab, name: string): SettingDefinitionRender {
  const row = flattenRows(tab.getSettingDefinitions()).find((candidate) => 'name' in candidate && candidate.name === name);
  if (row) {
    return castTo<SettingDefinitionRender>(row);
  }

  throw new Error(`Row not found: ${name}`);
}

/**
 * Flattens declared items into leaf rows, descending into groups and sub-pages alike.
 *
 * Both a group and a page carry their children in `items`, so the walk has to recurse: a page's rows sit one
 * level deeper than a top-level group's.
 *
 * @param items - The declared items.
 * @returns The leaf rows.
 */
function flattenRows(items: SettingDefinitionItem[]): SettingDefinition[] {
  const rows: SettingDefinition[] = [];
  for (const item of items) {
    if ('items' in item) {
      rows.push(...flattenRows(castTo<SettingDefinitionItem[]>(item.items ?? [])));
      continue;
    }

    rows.push(castTo<SettingDefinition>(item));
  }

  return rows;
}

/**
 * Evaluates a declared row's `disabled` predicate.
 *
 * @param tab - The settings tab.
 * @param name - The row name.
 * @returns Whether the row is disabled.
 */
function isRowDisabled(tab: PluginSettingsTab, name: string): boolean {
  const row = flattenRows(tab.getSettingDefinitions()).find((candidate) => 'name' in candidate && candidate.name === name);
  if (row) {
    return checkPredicate(castTo<DeclaredRow>(row).disabled, false);
  }

  throw new Error(`Row not found: ${name}`);
}

/**
 * Renders the declared rows the way Obsidian does when the tab is opened: it skips the rows whose `visible`
 * predicate is false, applies the name and description, runs the row's `render` callback, and finally applies
 * the `disabled` predicate (which `Setting.setDisabled` propagates to every component on the row).
 *
 * @param tab - The settings tab.
 */
function renderRows(tab: PluginSettingsTab): void {
  for (const row of flattenRows(tab.getSettingDefinitions())) {
    if (!('render' in row)) {
      continue;
    }

    const rowExtension = castTo<DeclaredRow>(row);
    if (!checkPredicate(rowExtension.visible, true)) {
      continue;
    }

    const setting = new SettingEx(tab.containerEl);
    setting.setName(row.name);
    if (row.desc) {
      setting.setDesc(row.desc);
    }

    row.render(setting, castTo<SettingGroup>(null));
    setting.setDisabled(checkPredicate(rowExtension.disabled, false));
  }
}

beforeAll(async () => {
  await initI18N(translationsMap);
  // Obsidian-dev-utils' bind() probes setPlaceholderValue to detect text-based components.
  for (
    const prototype of [
      ToggleComponentClass.prototype,
      DropdownComponentClass.prototype,
      TextComponentClass.prototype,
      ButtonComponentClass.prototype
    ]
  ) {
    if (!('setPlaceholderValue' in prototype)) {
      Object.defineProperty(prototype, 'setPlaceholderValue', { value: undefined });
    }
  }
});

describe('PluginSettingsTab', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    suggestedPluginState = SuggestedPluginState.Enabled;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Advanced Rename and Delete Handler suggestion banner', () => {
    it('should hand the row element to the suggestion component, emptied first', async () => {
      const { tab } = await createTab();
      const row = findRow(tab, '');
      const setting = new SettingEx(tab.containerEl);
      setting.setName('Leftover');

      row.render(setting, castTo<SettingGroup>(null));

      expect(renderBannerMock).toHaveBeenCalledWith(setting.settingEl);
      // Emptied first, so the Setting is a bare host rather than a row with a name beside a banner.
      expect(setting.settingEl.textContent).toBe('');
    });

    it('should hide itself once the suggested plugin is enabled', async () => {
      suggestedPluginState = SuggestedPluginState.Enabled;
      const { tab } = await createTab();
      expect(findRow(tab, '').visible?.()).toBe(false);
    });

    it('should show itself while the suggested plugin is not enabled', async () => {
      suggestedPluginState = SuggestedPluginState.NotInstalled;
      const { tab } = await createTab();
      expect(findRow(tab, '').visible?.()).toBe(true);
    });

    // It is not a setting, so it must not surface as one in Obsidian's settings search.
    it('should stay out of the settings search', async () => {
      const { tab } = await createTab();
      expect(findRow(tab, '').searchable).toBe(false);
    });
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
    expect(names).toContain('Renamed attachment file name');
    expect(names).toContain('Move attachment to proper folder used by multiple notes mode');
    expect(names).toContain('Special characters');
    expect(names).toContain('Special characters replacement');
    expect(names).toContain('Should rename collected attachments');
    expect(names).toContain('Collected attachment file name');
    expect(names).toContain('Collect attachment used by multiple notes mode');
    expect(names).toContain('Skip collecting attachments referenced by a raw path');
    expect(names).toContain('Default image size');
    expect(names).toContain('Convert images to JPEG mode');
    expect(names).toContain('JPEG Quality');
    expect(names).toContain('Attachment unit folders');
    expect(names).toContain('Exclude paths from attachment collecting');
    expect(names).toContain('Custom tokens');
    expect(names).toContain('Markdown URL format');
    expect(names).toContain('Timeout in seconds');
  });

  it('should keep Core inline and expose every other group as a navigable sub-page', async () => {
    const { tab } = await createTab();
    // The suggestion banner rides at the top as a bare ROW: Obsidian never calls `display()` once the
    // Declarative definitions are non-empty, so there is nowhere else to put it.
    const [banner, coreGroup, ...pages] = tab.getSettingDefinitions();
    expect(castTo<SettingDefinitionRender>(banner).name).toBe('');

    const core = castTo<SettingDefinitionGroup>(coreGroup);
    expect(core.type).toBe('group');
    expect(core.heading).toBe('Core');

    expect(pages.map((page) => castTo<SettingDefinitionPage>(page).name)).toEqual([
      'Move/renames',
      'Special characters',
      'Collected attachments',
      'Images',
      'Path',
      'Custom tokens',
      'Advanced'
    ]);

    for (const page of pages) {
      const settingPage = castTo<SettingDefinitionPage>(page);
      expect(settingPage.type).toBe('page');
      // A page entry with no description reads as a bare label on the parent tab, which is the scrolling problem again.
      expect(settingPage.desc).toBeTypeOf('string');
      expect(settingPage.desc).not.toBe('');
    }
  });

  it('should keep every declared row reachable after the split into sub-pages', async () => {
    const { tab } = await createTab();
    expect(flattenRows(tab.getSettingDefinitions())).toHaveLength(EXPECTED_ROW_COUNT);
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

  it('should cancel the debounced custom-token registration when the row is torn down', async () => {
    const { tab } = await createTab();

    // Obsidian calls the cleanup a row's `render` returns before the row is re-rendered or removed.
    const row = findRow(tab, 'Custom tokens');
    const setting = new SettingEx(tab.containerEl);
    setting.setName(row.name);
    const cleanup = row.render(setting, castTo<SettingGroup>(null));

    expect(cleanup).toBeTypeOf('function');
    expect(() => {
      castTo<() => void>(cleanup)();
    }).not.toThrow();
  });

  it('should re-evaluate the predicates when the download-network-images toggle changes', async () => {
    const { tab, toggles } = await createTab();

    const refreshDomStateSpy = vi.fn();
    tab.refreshDomState = refreshDomStateSpy;
    const captured = toggles.find((entry) => entry.name === 'Download network images');
    expect(captured).toBeDefined();
    captured?.toggle.setValue(true);
    await waitForAllAsyncOperations();
    expect(refreshDomStateSpy).toHaveBeenCalled();
  });

  it('should render the network image download timeout setting when downloading is enabled', async () => {
    const { names } = await createTab((settings) => {
      settings.downloadNetworkImages = true;
    });
    expect(names).toContain('Network image download timeout in seconds');
  });

  it('should not render the network image download timeout setting when downloading is disabled', async () => {
    const { names } = await createTab();
    expect(names).not.toContain('Network image download timeout in seconds');
  });

  it('should re-evaluate the predicates when the convert-images-to-JPEG dropdown changes', async () => {
    const { tab, textLikeComponents } = await createTab();

    const refreshDomStateSpy = vi.fn();
    tab.refreshDomState = refreshDomStateSpy;
    const captured = textLikeComponents.find((entry) => entry.name === 'Convert images to JPEG mode');
    expect(captured).toBeDefined();
    captured?.setValue(ConvertImagesToJpegMode.AllImages);
    await waitForAllAsyncOperations();
    expect(refreshDomStateSpy).toHaveBeenCalled();
  });

  it('should disable the preserve-metadata row while nothing is being converted', async () => {
    // Nothing is re-encoded in `None` mode, so there is no metadata loss for the row to prevent.
    const { tab } = await createTab();
    expect(isRowDisabled(tab, 'Should preserve image metadata')).toBe(true);
  });

  it('should enable the preserve-metadata row once images are converted', async () => {
    const { tab } = await createTab((settings) => {
      settings.convertImagesToJpegMode = ConvertImagesToJpegMode.AllImages;
    });
    expect(isRowDisabled(tab, 'Should preserve image metadata')).toBe(false);
  });

  it('should do nothing when resetting custom tokens that already match the sample', async () => {
    const { buttons, pluginSettingsComponent } = await createTab();
    await pluginSettingsComponent.editAndSave((settings) => {
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
      settings.customTokensStr = SAMPLE_CUSTOM_TOKENS;
    });
    const button = getResetButton(buttons);
    button.simulateClick__();
    await waitForAllAsyncOperations();
    expect(confirm).not.toHaveBeenCalled();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe(SAMPLE_CUSTOM_TOKENS);
  });

  it('should reset custom tokens directly when there is no existing code', async () => {
    const { buttons, pluginSettingsComponent } = await createTab();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe('');
    const button = getResetButton(buttons);
    button.simulateClick__();
    await waitForAllAsyncOperations();
    expect(confirm).not.toHaveBeenCalled();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe(SAMPLE_CUSTOM_TOKENS);
  });

  it('should reset custom tokens after confirmation when existing code is present', async () => {
    vi.mocked(confirm).mockResolvedValue(true);
    const { buttons, pluginSettingsComponent } = await createTab();
    await pluginSettingsComponent.editAndSave((settings) => {
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
      settings.customTokensStr = 'registerCustomToken(\'foo\', () => \'bar\');';
    });
    const button = getResetButton(buttons);
    button.simulateClick__();
    await waitForAllAsyncOperations();
    expect(confirm).toHaveBeenCalled();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe(SAMPLE_CUSTOM_TOKENS);
  });

  it('should keep custom tokens when the reset confirmation is cancelled', async () => {
    vi.mocked(confirm).mockResolvedValue(false);
    const { buttons, pluginSettingsComponent } = await createTab();
    const existingCode = 'registerCustomToken(\'foo\', () => \'bar\');';
    await pluginSettingsComponent.editAndSave((settings) => {
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
      settings.customTokensStr = existingCode;
    });
    const button = getResetButton(buttons);
    button.simulateClick__();
    await waitForAllAsyncOperations();
    expect(confirm).toHaveBeenCalled();
    expect(pluginSettingsComponent.settings.customTokensStr).toBe(existingCode);
  });

  it('should normalize and trim the attachment folder path when its value changes', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Location for new attachments');
    component.setValue('assets/folder   ');
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.attachmentFolderPath).toBe('assets/folder');
  });

  it('should store the duplicate name separator with restored space characters', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Duplicate name separator');
    component.setValue('␣');
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.duplicateNameSeparator).toBe(' ');
  });

  it('should store the special characters with restored space characters', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Special characters');
    component.setValue('a␣b');
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.specialCharacters).toBe('a b');
  });

  it('should store the special characters replacement with restored space characters', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Special characters replacement');
    component.setValue('x␣y');
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.specialCharactersReplacement).toBe('x y');
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
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.jpegQuality).toBe(0.5);
  });

  it('should bind the attachment rename mode dropdown', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Attachment rename mode');
    component.setValue(AttachmentRenameMode.All);
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.attachmentRenameMode).toBe(AttachmentRenameMode.All);
  });

  it('should bind the default image size text field', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Default image size');
    component.setValue('300px');
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.defaultImageSize).toBe('300px');
  });

  it('should bind the timeout number field', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Timeout in seconds');
    component.setValue('42');
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.timeoutInSeconds).toBe(42);
  });

  it('should bind a multiple-text field', async () => {
    const { multipleTextComponents, pluginSettingsComponent } = await createTab();
    const component = findMultipleTextComponent(multipleTextComponents, 'Exclude paths from attachment collecting');
    component.setValue(['foo/bar']);
    await waitForAllAsyncOperations();
    expect(pluginSettingsComponent.settings.excludePathsFromAttachmentCollecting).toStrictEqual(['foo/bar']);
  });

  it('should re-register custom tokens when the custom tokens code changes', async () => {
    const { pluginSettingsComponent, textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Custom tokens');
    component.setValue('registerCustomToken(\'qux\', () => \'quux\');');
    await waitForAllAsyncOperations();
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
      await waitForAllAsyncOperations();
      expect(revalidateSpy).toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  }, DEBOUNCE_REVALIDATION_TEST_TIMEOUT_IN_MILLISECONDS);

  it('should default the caret offsets to zero when the input reports no selection', async () => {
    const { textLikeComponents } = await createTab();
    const component = findComponent(textLikeComponents, 'Duplicate name separator');
    const inputEl = component.inputEl;
    expect(inputEl).toBeDefined();
    if (!inputEl) {
      return;
    }
    Object.defineProperties(inputEl, {
      selectionEnd: { configurable: true, value: null },
      selectionStart: { configurable: true, value: null }
    });
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

function findMultipleTextComponent(components: CapturedMultipleTextComponent[], name: string): CapturedMultipleTextComponent {
  const component = components.find((entry) => entry.name === name);
  if (!component) {
    throw new Error(`Multiple-text component "${name}" was not captured.`);
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
