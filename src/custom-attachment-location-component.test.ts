import type {
  App as AppOriginal,
  MarkdownView as MarkdownViewOriginal,
  TFile,
  Workspace,
  WorkspaceLeaf
} from 'obsidian';

import { ViewType } from '@obsidian-typings/obsidian-public-latest/implementations';
import { noopAsync } from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  App,
  MenuItem
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

import type { ArrayBufferMap } from './array-buffer-map.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { ImageSizeMap } from './image-size-map.ts';
import type { MarkdownUrlMap } from './markdown-url-map.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';
import type { TokenValidator } from './token-validator.ts';

import { translationsMap } from './i18n/locales/translations-map.ts';

interface CapturedChild {
  params: unknown;
  type: string;
}

type EventHandler = (...args: unknown[]) => unknown;

interface EventOnSpy {
  mock: EventOnSpyMock;
}

interface EventOnSpyMock {
  calls: [string, EventHandler][];
}

interface FileChildParams {
  readonly file: File;
}

type GenerateMarkdownLinkFn = (file: TFile, sourcePath: string) => string;

interface GenerateMarkdownLinkHolder {
  generateMarkdownLink: GenerateMarkdownLinkFn;
}

interface LayoutReadyTrigger {
  setLayoutReady__(): void;
}

interface MarkdownLeafEditMode {
  clipboardManager: object;
}

interface MarkdownLeafView {
  editMode: MarkdownLeafEditMode;
  getViewType(): string;
}

interface MenuItemLike {
  callback?(): void;
  iconEl: HTMLElement;
}

interface MenuLike {
  items: MenuItemLike[];
}

interface ObsidianComponentModule {
  Component: new () => object;
}

type ReplaceSelectionFn = (replacement: string, origin?: string) => void;

interface ShareReceiverHolder {
  shareReceiver: object;
}

const hoisted = vi.hoisted(() => ({
  capturedChildren: [] as CapturedChild[],
  isWebUtilsAvailable: true
}));

vi.mock('electron', () => ({
  get webUtils(): Pick<Electron.WebUtils, 'getPathForFile'> | undefined {
    return hoisted.isWebUtilsAvailable
      ? { getPathForFile: (_file: File): string => '/abs/path' }
      : undefined;
  }
}));

vi.mock('./substitutions.ts', () => ({
  Substitutions: {
    registerCustomTokens: vi.fn()
  }
}));

vi.mock('./patches/clipboard-manager-insert-files-patch-component.ts', async () => ({
  ClipboardManagerInsertFilesPatchComponent: await createChildStub('ClipboardManagerInsertFilesPatchComponent')
}));

vi.mock('./patches/file-array-buffer-patch-component.ts', async () => ({
  FileArrayBufferPatchComponent: await createChildStub('FileArrayBufferPatchComponent')
}));

vi.mock('./patches/file-manager-generate-markdown-link-patch-component.ts', async () => ({
  FileManagerGenerateMarkdownLinkPatchComponent: await createChildStub('FileManagerGenerateMarkdownLinkPatchComponent')
}));

vi.mock('./patches/share-receiver-import-files-patch-component.ts', async () => ({
  ShareReceiverImportFilesPatchComponent: await createChildStub('ShareReceiverImportFilesPatchComponent')
}));

vi.mock('./patches/vault-get-available-path-for-attachments-patch-component.ts', async () => ({
  VaultGetAvailablePathForAttachmentsPatchComponent: await createChildStub('VaultGetAvailablePathForAttachmentsPatchComponent')
}));

vi.mock('./patches/vault-get-available-path-patch-component.ts', async () => ({
  VaultGetAvailablePathPatchComponent: await createChildStub('VaultGetAvailablePathPatchComponent')
}));

vi.mock('./patches/vault-get-config-patch-component.ts', async () => ({
  VaultGetConfigPatchComponent: await createChildStub('VaultGetConfigPatchComponent')
}));

vi.mock('./patches/web-utils-get-path-for-file-patch-component.ts', async () => ({
  WebUtilsGetPathForFilePatchComponent: await createChildStub('WebUtilsGetPathForFilePatchComponent')
}));

/* eslint-disable import-x/first, import-x/imports-first -- vi.mock must precede imports. */
import { CustomAttachmentLocationComponent } from './custom-attachment-location-component.ts';
import { Substitutions } from './substitutions.ts';
/* eslint-enable import-x/first, import-x/imports-first -- vi.mock must precede imports. */

interface ComponentContext {
  app: AppOriginal;
  attachmentPathManager: AttachmentPathManager;
  editAndSaveMock: ReturnType<typeof vi.fn>;
  getActiveFileMock: ReturnType<typeof vi.fn>;
  getActiveViewOfTypeMock: ReturnType<typeof vi.fn>;
  getAttachmentFolderFullPathForPathMock: ReturnType<typeof vi.fn>;
  getLeavesOfTypeMock: ReturnType<typeof vi.fn>;
  loadFromFileMock: ReturnType<typeof vi.fn>;
  pluginSettingsComponent: PluginSettingsComponent;
  settings: PluginSettings;
}

const PLUGIN_VERSION = '10.0.0';

let context: ComponentContext;

const loadedComponents: CustomAttachmentLocationComponent[] = [];

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('CustomAttachmentLocationComponent', () => {
  beforeEach(() => {
    hoisted.capturedChildren.length = 0;
    hoisted.isWebUtilsAvailable = true;
    vi.useFakeTimers();

    const settings = strictProxy<PluginSettings>({
      customTokensStr: 'custom-tokens',
      isPathIgnored: vi.fn((_path: string): boolean => false),
      version: ''
    });

    const editAndSaveMock = vi.fn((editor: (settings: PluginSettings) => void): Promise<void> => {
      editor(settings);
      return noopAsync();
    });
    const loadFromFileMock = vi.fn((): Promise<void> => noopAsync());

    const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      editAndSave: editAndSaveMock,
      loadFromFile: loadFromFileMock,
      settings
    });

    const getAttachmentFolderFullPathForPathMock = vi.fn((): Promise<string> => Promise.resolve('attachments/note'));
    const attachmentPathManager = strictProxy<AttachmentPathManager>({
      getAttachmentFolderFullPathForPath: getAttachmentFolderFullPathForPathMock
    });

    const app = App.createConfigured__().asOriginalType__();
    const getActiveFileMock = vi.fn((): null | TFile => null);
    const getActiveViewOfTypeMock = vi.fn((): unknown => null);
    const getLeavesOfTypeMock = vi.fn((): WorkspaceLeaf[] => []);
    castTo<Pick<Workspace, 'getActiveFile'>>(app.workspace).getActiveFile = getActiveFileMock;
    castTo<Pick<Workspace, 'getActiveViewOfType'>>(app.workspace).getActiveViewOfType = getActiveViewOfTypeMock;
    castTo<Pick<Workspace, 'getLeavesOfType'>>(app.workspace).getLeavesOfType = getLeavesOfTypeMock;
    castTo<ShareReceiverHolder>(app).shareReceiver = {};

    context = {
      app,
      attachmentPathManager,
      editAndSaveMock,
      getActiveFileMock,
      getActiveViewOfTypeMock,
      getAttachmentFolderFullPathForPathMock,
      getLeavesOfTypeMock,
      loadFromFileMock,
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

  describe('currentAttachmentFolderPath', () => {
    it('should be null initially', () => {
      const component = createComponent();
      expect(component.currentAttachmentFolderPath).toBeNull();
    });
  });

  describe('onload', () => {
    it('should register file-open, rename and menu events', () => {
      const component = createComponent();
      const workspaceOnSpy = spyOnWorkspaceOn();
      const vaultOnSpy = spyOnVaultOn();
      component.load();
      const workspaceEventNames = workspaceOnSpy.mock.calls.map((call) => call[0]);
      expect(workspaceEventNames).toContain('file-open');
      expect(workspaceEventNames).toContain('receive-text-menu');
      expect(workspaceEventNames).toContain('receive-files-menu');
      expect(vaultOnSpy.mock.calls.map((call) => call[0])).toContain('rename');
    });
  });

  describe('onLayoutReady', () => {
    it('should register custom tokens and load settings from file', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      expect(vi.mocked(Substitutions.registerCustomTokens)).toHaveBeenCalledWith('custom-tokens');
      expect(context.loadFromFileMock).toHaveBeenCalledWith(false);
    });

    it('should add the vault, file-manager and share-receiver patch children', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      const types = capturedChildTypes();
      expect(types).toContain('VaultGetAvailablePathForAttachmentsPatchComponent');
      expect(types).toContain('VaultGetAvailablePathPatchComponent');
      expect(types).toContain('VaultGetConfigPatchComponent');
      expect(types).toContain('FileManagerGenerateMarkdownLinkPatchComponent');
      expect(types).toContain('ShareReceiverImportFilesPatchComponent');
    });

    it('should add the web-utils patch child when web utils are available', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      expect(capturedChildTypes()).toContain('WebUtilsGetPathForFilePatchComponent');
    });

    it('should not add the web-utils patch child when web utils are unavailable on the platform', async () => {
      hoisted.isWebUtilsAvailable = false;
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      expect(capturedChildTypes()).not.toContain('WebUtilsGetPathForFilePatchComponent');
      expect(capturedChildTypes()).toContain('VaultGetConfigPatchComponent');
    });

    it('should register an active-leaf-change event when no markdown view is patched', async () => {
      const component = createComponent();
      const workspaceOnSpy = spyOnWorkspaceOn();
      await loadAndReachLayoutReady(component);
      expect(workspaceOnSpy.mock.calls.map((call) => call[0])).toContain('active-leaf-change');
    });

    it('should patch the markdown view and skip the active-leaf-change event when a markdown leaf already exists', async () => {
      const component = createComponent();
      context.getLeavesOfTypeMock.mockReturnValue([createMarkdownLeaf(ViewType.Markdown)]);
      const workspaceOnSpy = spyOnWorkspaceOn();
      await loadAndReachLayoutReady(component);
      expect(capturedChildTypes()).toContain('ClipboardManagerInsertFilesPatchComponent');
      expect(workspaceOnSpy.mock.calls.map((call) => call[0])).not.toContain('active-leaf-change');
    });
  });

  describe('handleFileOpen', () => {
    it('should clear the state when the file is null', async () => {
      const component = createComponent();
      const handler = loadAndGetWorkspaceHandler(component, 'file-open');
      handler(null);
      await vi.runAllTimersAsync();
      expect(component.currentAttachmentFolderPath).toBeNull();
    });

    it('should clear the state when the path is ignored', async () => {
      const component = createComponent();
      castTo<ReturnType<typeof vi.fn>>(context.settings.isPathIgnored).mockReturnValue(true);
      const handler = loadAndGetWorkspaceHandler(component, 'file-open');
      handler(strictProxy<TFile>({ path: 'ignored.md' }));
      await vi.runAllTimersAsync();
      expect(component.currentAttachmentFolderPath).toBeNull();
      expect(context.getAttachmentFolderFullPathForPathMock).not.toHaveBeenCalled();
    });

    it('should compute the attachment folder path for a new file', async () => {
      const component = createComponent();
      context.getAttachmentFolderFullPathForPathMock.mockResolvedValue('attachments/new');
      const handler = loadAndGetWorkspaceHandler(component, 'file-open');
      handler(strictProxy<TFile>({ path: 'note.md' }));
      await vi.runAllTimersAsync();
      expect(component.currentAttachmentFolderPath).toBe('attachments/new');
    });

    it('should do nothing when the file is already the last opened file', async () => {
      const component = createComponent();
      const handler = loadAndGetWorkspaceHandler(component, 'file-open');
      handler(strictProxy<TFile>({ path: 'note.md' }));
      await vi.runAllTimersAsync();
      context.getAttachmentFolderFullPathForPathMock.mockClear();
      handler(strictProxy<TFile>({ path: 'note.md' }));
      await vi.runAllTimersAsync();
      expect(context.getAttachmentFolderFullPathForPathMock).not.toHaveBeenCalled();
    });
  });

  describe('handleRename', () => {
    it('should re-run handleFileOpen for the active file', async () => {
      const component = createComponent();
      context.getActiveFileMock.mockReturnValue(strictProxy<TFile>({ path: 'active.md' }));
      context.getAttachmentFolderFullPathForPathMock.mockResolvedValue('attachments/active');
      const handler = loadAndGetVaultHandler(component, 'rename');
      handler();
      await vi.runAllTimersAsync();
      expect(component.currentAttachmentFolderPath).toBe('attachments/active');
    });
  });

  describe('handleInputFileChange', () => {
    it('should ignore non-input targets', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      dispatchChange(activeDocument.createElement('div'));
      expect(capturedChildTypes()).not.toContain('FileArrayBufferPatchComponent');
    });

    it('should ignore non-file inputs', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      const input = activeDocument.createElement('input');
      input.type = 'text';
      dispatchChange(input);
      expect(capturedChildTypes()).not.toContain('FileArrayBufferPatchComponent');
    });

    it('should add a file array buffer patch child for each selected file', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      const input = activeDocument.createElement('input');
      input.type = 'file';
      const file = new File([new ArrayBuffer(4)], 'image.png');
      Object.defineProperty(input, 'files', { value: [file] });
      dispatchChange(input);
      const fileChildren = hoisted.capturedChildren.filter((child) => child.type === 'FileArrayBufferPatchComponent');
      expect(fileChildren).toHaveLength(1);
      expect(castTo<FileChildParams>(fileChildren[0]?.params).file).toBe(file);
    });

    it('should handle an input with no selected files', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      const input = activeDocument.createElement('input');
      input.type = 'file';
      Object.defineProperty(input, 'files', { value: null });
      dispatchChange(input);
      expect(capturedChildTypes()).not.toContain('FileArrayBufferPatchComponent');
    });
  });

  describe('handleReceiveTextMenu', () => {
    it('should set the matching menu item callback', () => {
      const component = createComponent();
      const handler = loadAndGetWorkspaceHandler(component, 'receive-text-menu');
      const menuItem = createMenuItem(true);
      handler(menuWith(menuItem), 'some text');
      expect(menuItem.callback).toBeDefined();
    });

    it('should do nothing when there is no matching menu item', () => {
      const component = createComponent();
      const handler = loadAndGetWorkspaceHandler(component, 'receive-text-menu');
      const menuItem = createMenuItem(false);
      handler(menuWith(menuItem), 'some text');
      expect(menuItem.callback).toBeUndefined();
    });

    it('should insert the text when the callback runs with an active markdown view', () => {
      const component = createComponent();
      const replaceSelection = vi.fn<ReplaceSelectionFn>();
      setActiveMarkdownView(replaceSelection, strictProxy<TFile>({ path: 'note.md' }));
      const handler = loadAndGetWorkspaceHandler(component, 'receive-text-menu');
      const menuItem = createMenuItem(true);
      handler(menuWith(menuItem), 'inserted text');
      menuItem.callback?.();
      expect(replaceSelection).toHaveBeenCalledWith('inserted text');
    });

    it('should not insert when there is no active markdown view file', () => {
      const component = createComponent();
      context.getActiveViewOfTypeMock.mockReturnValue(strictProxy<MarkdownViewOriginal>({ file: null }));
      const handler = loadAndGetWorkspaceHandler(component, 'receive-text-menu');
      const menuItem = createMenuItem(true);
      handler(menuWith(menuItem), 'inserted text');
      expect(() => menuItem.callback?.()).not.toThrow();
    });
  });

  describe('handleReceiveFilesMenu', () => {
    it('should build markdown links for the received attachment files', () => {
      const component = createComponent();
      const replaceSelection = vi.fn<ReplaceSelectionFn>();
      const generateMarkdownLinkMock = vi.fn((_file: TFile, _sourcePath: string): string => '[[link]]');
      castTo<GenerateMarkdownLinkHolder>(context.app.fileManager).generateMarkdownLink = generateMarkdownLinkMock;
      setActiveMarkdownView(replaceSelection, strictProxy<TFile>({ path: 'note.md' }));
      const handler = loadAndGetWorkspaceHandler(component, 'receive-files-menu');
      const menuItem = createMenuItem(true);
      handler(menuWith(menuItem), [strictProxy<TFile>({ path: 'a.png' }), strictProxy<TFile>({ path: 'b.png' })]);
      menuItem.callback?.();
      expect(generateMarkdownLinkMock).toHaveBeenCalledTimes(2);
      expect(replaceSelection).toHaveBeenCalledWith('[[link]]\n[[link]]');
    });
  });

  describe('handleActiveLeafChange', () => {
    it('should patch the clipboard manager when an active markdown leaf becomes available', async () => {
      const component = createComponent();
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      handler(createMarkdownLeaf(ViewType.Markdown));
      await vi.runAllTimersAsync();
      expect(capturedChildTypes()).toContain('ClipboardManagerInsertFilesPatchComponent');
    });

    it('should do nothing for a null leaf', async () => {
      const component = createComponent();
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      handler(null);
      await vi.runAllTimersAsync();
      expect(capturedChildTypes()).not.toContain('ClipboardManagerInsertFilesPatchComponent');
    });

    it('should do nothing for a non-markdown leaf', async () => {
      const component = createComponent();
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      handler(createMarkdownLeaf('other'));
      await vi.runAllTimersAsync();
      expect(capturedChildTypes()).not.toContain('ClipboardManagerInsertFilesPatchComponent');
    });

    it('should do nothing once the markdown view is already patched', async () => {
      const component = createComponent();
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      handler(createMarkdownLeaf(ViewType.Markdown));
      await vi.runAllTimersAsync();
      handler(createMarkdownLeaf(ViewType.Markdown));
      await vi.runAllTimersAsync();
      const clipboardChildCount = hoisted.capturedChildren.filter((child) => child.type === 'ClipboardManagerInsertFilesPatchComponent').length;
      expect(clipboardChildCount).toBe(1);
    });
  });

  describe('showReleaseNotes', () => {
    it('should persist the current version when there is no stored version', async () => {
      const component = createComponent();
      context.settings.version = '';
      await loadAndReachLayoutReady(component);
      expect(context.editAndSaveMock).toHaveBeenCalled();
      expect(context.settings.version).toBe(PLUGIN_VERSION);
    });

    it('should persist the current version and show release notes for newer versions', async () => {
      const component = createComponent();
      context.settings.version = '9.0.0';
      await loadAndReachLayoutReady(component);
      expect(context.editAndSaveMock).toHaveBeenCalled();
      expect(context.settings.version).toBe(PLUGIN_VERSION);
    });

    it('should show a version-mismatch warning and not persist when the stored version is newer', async () => {
      const component = createComponent();
      context.settings.version = '99.0.0';
      await loadAndReachLayoutReady(component);
      expect(context.editAndSaveMock).not.toHaveBeenCalled();
      expect(context.settings.version).toBe('99.0.0');
    });
  });
});

function capturedChildTypes(): string[] {
  return hoisted.capturedChildren.map((child) => child.type);
}

async function createChildStub(type: string): Promise<new (params: unknown) => object> {
  const { Component } = await vi.importActual<ObsidianComponentModule>('obsidian');
  return class extends Component {
    public constructor(params: unknown) {
      super();
      hoisted.capturedChildren.push({ params, type });
    }
  };
}

function createComponent(): CustomAttachmentLocationComponent {
  const component = new CustomAttachmentLocationComponent({
    app: context.app,
    arrayBufferMap: strictProxy<ArrayBufferMap>({}),
    attachmentPathManager: context.attachmentPathManager,
    imageSizeMap: strictProxy<ImageSizeMap>({}),
    markdownUrlMap: strictProxy<MarkdownUrlMap>({}),
    pluginDir: 'plugins/custom-attachment-location',
    pluginSettingsComponent: context.pluginSettingsComponent,
    pluginVersion: PLUGIN_VERSION,
    tokenValidator: strictProxy<TokenValidator>({})
  });
  loadedComponents.push(component);
  return component;
}

function createMarkdownLeaf(viewType: string): WorkspaceLeaf {
  const view = strictProxy<MarkdownLeafView>({
    editMode: { clipboardManager: {} },
    getViewType: (): string => viewType
  });
  return strictProxy<WorkspaceLeaf>({
    loadIfDeferred: vi.fn((): Promise<void> => noopAsync()),
    view: castTo<WorkspaceLeaf['view']>(view)
  });
}

function createMenuItem(hasFileIcon: boolean): MenuItemLike {
  const menuItem = castTo<MenuItemLike>(Object.create(MenuItem.prototype));
  menuItem.iconEl = activeDocument.createElement('div');
  if (hasFileIcon) {
    menuItem.iconEl.appendChild(activeDocument.createElement('div')).addClass('lucide-file');
  }
  return menuItem;
}

function dispatchChange(target: HTMLElement): void {
  const event = new Event('change');
  Object.defineProperty(event, 'target', { value: target });
  activeDocument.dispatchEvent(event);
}

function findHandler(spy: EventOnSpy, eventName: string): EventHandler {
  const call = spy.mock.calls.find((entry) => entry[0] === eventName);
  return castTo<EventHandler>(call?.[1]);
}

async function loadAndGetActiveLeafChangeHandler(component: CustomAttachmentLocationComponent): Promise<EventHandler> {
  const spy = spyOnWorkspaceOn();
  await loadAndReachLayoutReady(component);
  return findHandler(spy, 'active-leaf-change');
}

function loadAndGetVaultHandler(component: CustomAttachmentLocationComponent, eventName: string): EventHandler {
  const spy = spyOnVaultOn();
  component.load();
  return findHandler(spy, eventName);
}

function loadAndGetWorkspaceHandler(component: CustomAttachmentLocationComponent, eventName: string): EventHandler {
  const spy = spyOnWorkspaceOn();
  component.load();
  return findHandler(spy, eventName);
}

async function loadAndReachLayoutReady(component: CustomAttachmentLocationComponent): Promise<void> {
  component.load();
  castTo<LayoutReadyTrigger>(context.app.workspace).setLayoutReady__();
  await vi.runAllTimersAsync();
}

function menuWith(menuItem: MenuItemLike): MenuLike {
  return { items: [menuItem] };
}

function setActiveMarkdownView(replaceSelection: ReplaceSelectionFn, file: null | TFile): void {
  context.getActiveViewOfTypeMock.mockReturnValue(strictProxy<MarkdownViewOriginal>({
    editor: strictProxy<MarkdownViewOriginal['editor']>({ replaceSelection }),
    file
  }));
}

function spyOnVaultOn(): EventOnSpy {
  return castTo<EventOnSpy>(vi.spyOn(context.app.vault, 'on'));
}

function spyOnWorkspaceOn(): EventOnSpy {
  return castTo<EventOnSpy>(vi.spyOn(context.app.workspace, 'on'));
}
