import type {
  App as AppOriginal,
  MarkdownView as MarkdownViewOriginal,
  TFile,
  Workspace,
  WorkspaceLeaf
} from 'obsidian';

import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import {
  noop,
  noopAsync
} from '@mnaoumov/typescript-lib/function';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { ViewType } from '@obsidian-typings/obsidian-public-latest/implementations';
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

import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { ArrayBufferMap } from '../attachment-saving/array-buffer-map.ts';
import type { ImageSizeMap } from '../markdown-links/image-size-map.ts';
import type { MarkdownUrlMap } from '../markdown-links/markdown-url-map.ts';
import type { InsertGestureTrackerComponent } from '../pasted-images/insert-gesture-tracker-component.ts';
import type { PastedImageMarker } from '../pasted-images/pasted-image-marker.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { PluginSettings } from '../settings/plugin-settings.ts';
import type { SidecarAttachmentsComponent } from '../sidecars/sidecar-attachments-component.ts';
import type { TokenValidator } from '../tokens/token-validator.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';

interface CapturedChild {
  params: unknown;
  type: string;
}

type EventHandler = (...$arguments: unknown[]) => unknown;

interface EventOnSpy {
  mock: EventOnSpyMock;
}

interface EventOnSpyMock {
  calls: [string, EventHandler][];
}

interface FileChildParams {
  readonly file: File;
}

type GenerateMarkdownLinkFunction = (file: TFile, sourcePath: string) => string;

interface GenerateMarkdownLinkHolder {
  generateMarkdownLink: GenerateMarkdownLinkFunction;
}

interface InsertFilesChildParams {
  readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;
  readonly pastedImageMarker: PastedImageMarker;
  readonly sidecarAttachmentsComponent?: SidecarAttachmentsComponent;
}

interface LayoutReadyTrigger {
  setLayoutReady__: () => void;
}

interface MarkdownLeafEditMode {
  clipboardManager: object;
}

interface MarkdownLeafView {
  editMode: MarkdownLeafEditMode;
  getViewType: () => string;
}

interface MenuItemLike {
  callback?: () => void;
  iconEl: HTMLElement;
}

interface MenuLike {
  items: MenuItemLike[];
}

interface ObsidianComponentModule {
  Component: new () => object;
}

type ReplaceSelectionFunction = (replacement: string, origin?: string) => void;

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

vi.mock('../tokens/substitutions.ts', () => ({
  Substitutions: {
    registerCustomTokens: vi.fn()
  }
}));

vi.mock('../pasted-images/app-import-attachments-patch-component.ts', async () => ({
  AppImportAttachmentsPatchComponent: await createChildStub('AppImportAttachmentsPatchComponent')
}));

vi.mock('../pasted-images/clipboard-manager-insert-files-patch-component.ts', async () => ({
  ClipboardManagerInsertFilesPatchComponent: await createChildStub('ClipboardManagerInsertFilesPatchComponent')
}));

vi.mock('../settings/core-files-setting-tab-patch-component.ts', async () => ({
  CoreFilesSettingTabPatchComponent: await createChildStub('CoreFilesSettingTabPatchComponent')
}));

vi.mock('../attachment-saving/file-array-buffer-patch-component.ts', async () => ({
  FileArrayBufferPatchComponent: await createChildStub('FileArrayBufferPatchComponent')
}));

vi.mock('../markdown-links/file-manager-generate-markdown-link-patch-component.ts', async () => ({
  FileManagerGenerateMarkdownLinkPatchComponent: await createChildStub('FileManagerGenerateMarkdownLinkPatchComponent')
}));

vi.mock('./share-receiver-import-files-patch-component.ts', async () => ({
  ShareReceiverImportFilesPatchComponent: await createChildStub('ShareReceiverImportFilesPatchComponent')
}));

vi.mock('./vault-get-available-path-for-attachments-patch-component.ts', async () => ({
  VaultGetAvailablePathForAttachmentsPatchComponent: await createChildStub('VaultGetAvailablePathForAttachmentsPatchComponent')
}));

vi.mock('./vault-get-available-path-patch-component.ts', async () => ({
  VaultGetAvailablePathPatchComponent: await createChildStub('VaultGetAvailablePathPatchComponent')
}));

vi.mock('./vault-get-config-patch-component.ts', async () => ({
  VaultGetConfigPatchComponent: await createChildStub('VaultGetConfigPatchComponent')
}));

vi.mock('../pasted-images/web-utils-get-path-for-file-patch-component.ts', async () => ({
  WebUtilsGetPathForFilePatchComponent: await createChildStub('WebUtilsGetPathForFilePatchComponent')
}));

/* eslint-disable import-x/first, import-x/imports-first -- vi.mock must precede imports. */
import { Substitutions } from '../tokens/substitutions.ts';
import { CustomAttachmentLocationComponent } from './custom-attachment-location-component.ts';
/* eslint-enable import-x/first, import-x/imports-first -- vi.mock must precede imports. */

interface ComponentContext {
  app: AppOriginal;
  attachmentPathManager: AttachmentPathManager;
  getActiveFileMock: ReturnType<typeof vi.fn>;
  getActiveViewOfTypeMock: ReturnType<typeof vi.fn>;
  getAttachmentFolderFullPathForPathMock: ReturnType<typeof vi.fn>;
  getLeavesOfTypeMock: ReturnType<typeof vi.fn>;
  handedOverSettingsComponent: HandedOverSettingsComponent;
  isPathIgnoredMock: ReturnType<typeof vi.fn>;
  loadFromFileMock: ReturnType<typeof vi.fn>;
  pluginSettingsComponent: PluginSettingsComponent;
  settings: PluginSettings;
  whenLoadedFromFileMock: ReturnType<typeof vi.fn>;
}

let context: ComponentContext;

const loadedComponents: CustomAttachmentLocationComponent[] = [];

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('CustomAttachmentLocationComponent', () => {
  it('hands the sidecar batch component to the real editor interception', async () => {
    const sidecars = strictProxy<SidecarAttachmentsComponent>({});
    context.getLeavesOfTypeMock.mockReturnValue([createMarkdownLeaf(ViewType.Markdown)]);
    const component = createComponent(undefined, sidecars);
    await loadAndReachLayoutReady(component);
    const child = hoisted.capturedChildren.find((entry) => entry.type === 'ClipboardManagerInsertFilesPatchComponent');
    expect(castTo<InsertFilesChildParams>(child?.params).sidecarAttachmentsComponent).toBe(sidecars);
  });
  beforeEach(() => {
    hoisted.capturedChildren.length = 0;
    hoisted.isWebUtilsAvailable = true;
    vi.useFakeTimers();

    const settings = strictProxy<PluginSettings>({
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
      customTokensStr: 'custom-tokens',
      screenshotFilePaths: ['/PixPin_/'],
      shouldFollowObsidianAttachmentLocation: false,
      shouldKeepNamesOfPastedNonScreenshotFiles: true
    });

    const loadFromFileMock = vi.fn((): Promise<void> => noopAsync());
    const whenLoadedFromFileMock = vi.fn((): Promise<void> => noopAsync());

    const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      loadFromFile: loadFromFileMock,
      settings,
      whenLoadedFromFile: whenLoadedFromFileMock
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

    const isPathIgnoredMock = vi.fn((_path: string): boolean => false);
    const handedOverSettingsComponent = strictProxy<HandedOverSettingsComponent>({ isPathIgnored: isPathIgnoredMock });

    context = {
      app,
      attachmentPathManager,
      getActiveFileMock,
      getActiveViewOfTypeMock,
      getAttachmentFolderFullPathForPathMock,
      getLeavesOfTypeMock,
      handedOverSettingsComponent,
      isPathIgnoredMock,
      loadFromFileMock,
      pluginSettingsComponent,
      settings,
      whenLoadedFromFileMock
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
    it('should neither register custom tokens nor reload the settings, since loading them registers the tokens', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      expect(vi.mocked(Substitutions.registerCustomTokens)).not.toHaveBeenCalled();
      expect(context.loadFromFileMock).not.toHaveBeenCalled();
    });

    it('should not add the patch children until the settings have been read from the file', async () => {
      let resolve: () => void = noop;
      context.whenLoadedFromFileMock.mockReturnValue(
        new Promise<void>((promiseResolve) => {
          resolve = promiseResolve;
        })
      );
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      expect(capturedChildTypes()).not.toContain('VaultGetAvailablePathForAttachmentsPatchComponent');

      resolve();
      await vi.runAllTimersAsync();
      expect(capturedChildTypes()).toContain('VaultGetAvailablePathForAttachmentsPatchComponent');
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
      expect(types).toContain('CoreFilesSettingTabPatchComponent');
      expect(types).toContain('AppImportAttachmentsPatchComponent');
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
      context.isPathIgnoredMock.mockReturnValue(true);
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

    it('should resolve nothing while the plugin follows Obsidian\'s own attachment location', async () => {
      const component = createComponent();
      context.settings.shouldFollowObsidianAttachmentLocation = true;
      const handler = loadAndGetWorkspaceHandler(component, 'file-open');
      handler(strictProxy<TFile>({ path: 'note.md' }));
      await vi.runAllTimersAsync();
      expect(component.currentAttachmentFolderPath).toBeNull();
      expect(context.getAttachmentFolderFullPathForPathMock).not.toHaveBeenCalled();
    });

    it('should stop handing out a folder resolved before the mode was switched on', async () => {
      const component = createComponent();
      context.getAttachmentFolderFullPathForPathMock.mockResolvedValue('attachments/new');
      const handler = loadAndGetWorkspaceHandler(component, 'file-open');
      handler(strictProxy<TFile>({ path: 'note.md' }));
      await vi.runAllTimersAsync();
      expect(component.currentAttachmentFolderPath).toBe('attachments/new');

      // eslint-disable-next-line require-atomic-updates -- The test is the only writer; the switch is the point of it.
      context.settings.shouldFollowObsidianAttachmentLocation = true;
      expect(component.currentAttachmentFolderPath).toBeNull();
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
      dispatchChange(activeWindow.createDiv());
      expect(capturedChildTypes()).not.toContain('FileArrayBufferPatchComponent');
    });

    it('should ignore non-file inputs', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      const input = activeWindow.createEl('input');
      input.type = 'text';
      dispatchChange(input);
      expect(capturedChildTypes()).not.toContain('FileArrayBufferPatchComponent');
    });

    it('should add a file array buffer patch child for each selected file', async () => {
      const component = createComponent();
      await loadAndReachLayoutReady(component);
      const input = activeWindow.createEl('input');
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
      const input = activeWindow.createEl('input');
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
      const replaceSelection = vi.fn<ReplaceSelectionFunction>();
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
      const replaceSelection = vi.fn<ReplaceSelectionFunction>();
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

  describe('patchClipboardManagerFromLoadedMarkdownView', () => {
    it('should patch the clipboard manager when an active markdown leaf becomes available', async () => {
      const component = createComponent();
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      const leaf = createMarkdownLeaf(ViewType.Markdown);
      context.getLeavesOfTypeMock.mockReturnValue([leaf]);
      handler(leaf);
      await vi.runAllTimersAsync();
      expect(capturedChildTypes()).toContain('ClipboardManagerInsertFilesPatchComponent');
    });

    it('should patch the clipboard manager on a layout change that loads a markdown view', async () => {
      const component = createComponent();
      const spy = spyOnWorkspaceOn();
      await loadAndReachLayoutReady(component);
      context.getLeavesOfTypeMock.mockReturnValue([createMarkdownLeaf(ViewType.Markdown)]);
      findHandler(spy, 'layout-change')();
      expect(capturedChildTypes()).toContain('ClipboardManagerInsertFilesPatchComponent');
    });

    it('should leave a deferred markdown leaf unloaded and wait for a loaded one', async () => {
      const component = createComponent();
      context.getLeavesOfTypeMock.mockReturnValue([createMarkdownLeaf(ViewType.Markdown, true)]);
      const workspaceOnSpy = spyOnWorkspaceOn();
      await loadAndReachLayoutReady(component);
      expect(capturedChildTypes()).not.toContain('ClipboardManagerInsertFilesPatchComponent');
      expect(workspaceOnSpy.mock.calls.map((call) => call[0])).toEqual(expect.arrayContaining(['active-leaf-change', 'layout-change']));
    });

    it('should patch through a loaded markdown leaf that follows a deferred one', async () => {
      const component = createComponent();
      context.getLeavesOfTypeMock.mockReturnValue([createMarkdownLeaf(ViewType.Markdown, true), createMarkdownLeaf(ViewType.Markdown)]);
      await loadAndReachLayoutReady(component);
      expect(capturedChildTypes()).toContain('ClipboardManagerInsertFilesPatchComponent');
    });

    it('should hand the clipboard manager patch the gesture tracker, and a marker that reads the screenshot paths', async () => {
      const markAsPastedImageMock = vi.fn();
      const component = createComponent(strictProxy<ArrayBufferMap>({
        getFileStats: () => undefined,
        markAsPastedImage: markAsPastedImageMock,
        trySetByPath: () => Promise.resolve(false)
      }));
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      const leaf = createMarkdownLeaf(ViewType.Markdown);
      context.getLeavesOfTypeMock.mockReturnValue([leaf]);
      handler(leaf);
      await vi.runAllTimersAsync();
      const child = hoisted.capturedChildren.find((entry) => entry.type === 'ClipboardManagerInsertFilesPatchComponent');
      const params = castTo<InsertFilesChildParams>(child?.params);
      expect(params.insertGestureTrackerComponent.gesture).toBeNull();

      const arrayBuffer = new ArrayBuffer(4);
      await params.pastedImageMarker.record([{
        data: Promise.resolve(arrayBuffer),
        extension: 'png',
        filepath: 'C:/Temp/PixPin_2026-10-16_22-00-00.png',
        name: 'PixPin_2026-10-16_22-00-00'
      }], null);
      expect(markAsPastedImageMock).toHaveBeenCalledWith(arrayBuffer);
    });

    it('should do nothing for a null leaf', async () => {
      const component = createComponent();
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      handler(null);
      await vi.runAllTimersAsync();
      expect(capturedChildTypes()).not.toContain('ClipboardManagerInsertFilesPatchComponent');
    });

    it('should do nothing for a markdown leaf whose loaded view is not a markdown view', async () => {
      const component = createComponent();
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      const leaf = createMarkdownLeaf('empty');
      context.getLeavesOfTypeMock.mockReturnValue([leaf]);
      handler(leaf);
      await vi.runAllTimersAsync();
      expect(capturedChildTypes()).not.toContain('ClipboardManagerInsertFilesPatchComponent');
    });

    it('should do nothing once the markdown view is already patched', async () => {
      const component = createComponent();
      const handler = await loadAndGetActiveLeafChangeHandler(component);
      context.getLeavesOfTypeMock.mockReturnValue([createMarkdownLeaf(ViewType.Markdown)]);
      handler(null);
      await vi.runAllTimersAsync();
      handler(null);
      await vi.runAllTimersAsync();
      const clipboardChildCount = hoisted.capturedChildren.filter((child) => child.type === 'ClipboardManagerInsertFilesPatchComponent').length;
      expect(clipboardChildCount).toBe(1);
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

function createComponent(arrayBufferMap = strictProxy<ArrayBufferMap>({}), sidecarAttachmentsComponent?: SidecarAttachmentsComponent): CustomAttachmentLocationComponent {
  const component = new CustomAttachmentLocationComponent({
    app: context.app,
    arrayBufferMap,
    attachmentPathManager: context.attachmentPathManager,
    handedOverSettingsComponent: context.handedOverSettingsComponent,
    imageSizeMap: strictProxy<ImageSizeMap>({}),
    markdownUrlMap: strictProxy<MarkdownUrlMap>({}),
    pluginId: 'custom-attachment-location',
    pluginName: 'Custom Attachment Location',
    pluginSettingsComponent: context.pluginSettingsComponent,
    ...sidecarAttachmentsComponent && { sidecarAttachmentsComponent },
    tokenValidator: strictProxy<TokenValidator>({})
  });
  loadedComponents.push(component);
  return component;
}

// The leaf carries no `loadIfDeferred`, so the strict proxy throws if the component ever tries to load one.
function createMarkdownLeaf(viewType: string, isDeferred = false): WorkspaceLeaf {
  const view = strictProxy<MarkdownLeafView>({
    editMode: { clipboardManager: {} },
    getViewType: (): string => viewType
  });
  return strictProxy<WorkspaceLeaf>({
    isDeferred,
    view: castTo<WorkspaceLeaf['view']>(view)
  });
}

function createMenuItem(hasFileIcon: boolean): MenuItemLike {
  const menuItem = castTo<MenuItemLike>(Object.create(MenuItem.prototype));
  menuItem.iconEl = activeWindow.createDiv();
  if (hasFileIcon) {
    const fileIconEl = activeWindow.createDiv();
    fileIconEl.addClass('lucide-file');
    menuItem.iconEl.append(fileIconEl);
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

function setActiveMarkdownView(replaceSelection: ReplaceSelectionFunction, file: null | TFile): void {
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
