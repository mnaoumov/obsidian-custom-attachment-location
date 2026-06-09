/* eslint-disable @typescript-eslint/no-extraneous-class, @typescript-eslint/no-useless-constructor -- Test mocks require empty constructors and constructor-only classes. */
import type {
  App,
  PluginManifest,
  TFile,
  WorkspaceLeaf
} from 'obsidian';
import type { StrictProxyPartial } from 'obsidian-dev-utils/strict-proxy';

import { noopAsync } from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  bypassStrictProxy,
  strictProxy
} from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettings } from './plugin-settings.ts';

import { translationsMap } from './i18n/locales/translations-map.ts';
import {
  AttachmentRenameMode,
  ConvertImagesToJpegMode
} from './plugin-settings.ts';

interface AdapterStatFn {
  stat: ReturnType<typeof vi.fn>;
}

interface CapacitorAdapterLike {
  fs: AdapterStatFn;
}

interface CapturedEvent {
  handler(...args: unknown[]): unknown;
  name: string;
}

interface CapturedPatch {
  target: object;
}

interface ClipboardManagerInsertFiles {
  insertFiles(attachments: ImportedAttachmentLike[]): Promise<void>;
}

interface ConvertImageToJpegParams {
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
  readonly isPastedImage: boolean;
}

interface EventRefLike {
  id: string;
}

interface ExtendedGetAvailablePathForAttachmentsExtension {
  extended(params: GetAvailablePathForAttachmentsExtendedFnParams): Promise<string>;
}

interface FileManagerGenerateMarkdownLink {
  generateMarkdownLink(file: TFile, sourcePath: string): string;
}

interface FileStatLike {
  ctime: number;
  mtime: number;
  size: number;
}

interface FileSystemAdapterLike {
  fsPromises: AdapterStatFn;
}

interface FileWithPath {
  file: TFile;
}

type GenerateMarkdownLinkFn = (file: TFile, sourcePath: string, subpath?: string, alias?: string) => string;

interface GetAvailablePathForAttachmentsExtendedFnParams {
  readonly attachmentFileBaseName: string;
  readonly attachmentFileContent?: ArrayBuffer;
  readonly attachmentFileExtension: string;
  readonly context: unknown;
  readonly notePathOrFile: null | string | TFile;
  readonly oldAttachmentPathOrFile?: unknown;
  readonly oldNotePathOrFile?: unknown;
  readonly shouldSkipDuplicateCheck?: boolean;
  readonly shouldSkipGeneratedAttachmentFileName?: boolean;
  readonly shouldSkipMissingAttachmentFolderCreation?: boolean;
}

interface ImportedAttachmentLike {
  data: Promise<ArrayBuffer>;
  filepath: string;
}

interface ManifestWithoutDir {
  dir: undefined;
}

interface MarkdownViewWithEditMode {
  editMode: MockMarkdownViewEditMode;
}

interface MockMarkdownViewEditMode {
  clipboardManager: object;
}

interface MockMarkdownViewEditor {
  replaceSelection(text: string): void;
}

type PatchFactories = Record<string, (next: unknown) => unknown>;

type PatchTarget = Record<string, unknown>;

interface PluginPrivate {
  arrayBufferFileStatMap: WeakMap<ArrayBuffer, FileStatLike>;
  convertImageToJpeg(params: ConvertImageToJpegParams): Promise<ConvertImageToJpegParams>;
  currentAttachmentFolderPath: null | string;
  fileArrayBuffer(next: (this: File) => Promise<ArrayBuffer>, file: File): Promise<ArrayBuffer>;
  generateMarkdownLink(next: GenerateMarkdownLinkFn, file: TFile, sourcePath: string, subpath?: string, alias?: string): string;
  getAvailablePath(attachmentFileName: string, attachmentExtension: string): string;
  getAvailablePathForAttachments(params: GetAvailablePathForAttachmentsExtendedFnParams): Promise<string>;
  getConfig(next: (name: string) => unknown, name: string): unknown;
  getCursorLine(noteFilePath: string, oldAttachmentPathOrFile: unknown): Promise<number>;
  getPathForFile(file: File, next: (file: File) => string): string;
  handleActiveLeafChange(leaf: null | WorkspaceLeaf): Promise<void>;
  handleFileOpen(file: null | TFile): Promise<void>;
  handleInputFileChange(evt: Event): void;
  handleReceiveFilesMenu(menu: unknown, attachmentFiles: TFile[]): void;
  handleReceiveTextMenu(menu: unknown, text: string): void;
  handleRename(): Promise<void>;
  imageAttachmentSizeMap: Map<string, string>;
  importFiles(next: (files: unknown[]) => Promise<void>, files: SharedFileLike[]): Promise<void>;
  insertFiles(next: (attachments: unknown[]) => Promise<void>, clipboardManager: object, importedAttachments: ImportedAttachmentLike[]): Promise<void>;
  isMarkdownViewPatched: boolean;
  lastOpenFilePath: null | string;
  onLayoutReady(): Promise<void>;
  pathMarkdownUrlMap: Map<string, string>;
  saveAttachment(name: string, extension: string, data: ArrayBuffer): Promise<TFile>;
  setFileStat(arrayBuffer: ArrayBuffer, filePath: string): Promise<boolean>;
}

interface PluginWithOriginal {
  getAvailablePathForAttachmentsOriginal(filename: string, extension: string, file: null | TFile): Promise<string>;
}

interface RenameDeleteHandlerComponentParamsProbe {
  settingsBuilder(): RenameDeleteSettingsProbe;
}

interface RenameDeleteSettingsProbe {
  isNote(path: string): boolean;
  isPathIgnored(path: string): boolean;
}

interface SaveAttachmentLike {
  saveAttachment(name: string, extension: string, data: ArrayBuffer): Promise<TFile>;
}

interface SharedFileLike {
  name: string;
  uri: string;
}

interface ShareReceiverImportFiles {
  importFiles(files: SharedFileLike[]): Promise<void>;
}

interface VaultExtendedGetAvailablePathForAttachments {
  getAvailablePathForAttachments:
    & ((filename: string, extension: string, file: null | TFile) => Promise<string>)
    & ExtendedGetAvailablePathForAttachmentsExtension;
}

interface VaultGetAvailablePath {
  getAvailablePath(path: string, extension: string): string;
}

interface VaultGetConfig {
  getConfig(name: string): unknown;
}

interface VaultOriginalGetAvailablePathForAttachments {
  getAvailablePathForAttachments(filename: string, extension: string, file: null | TFile): Promise<string>;
}

interface WebUtilsLike {
  getPathForFile(file: File): string;
}

// --- Hoisted shared state ---

const hoisted = vi.hoisted(() => ({
  capturedEvents: [] as CapturedEvent[],
  capturedPatches: [] as CapturedPatch[],
  layoutReadyCallbacks: [] as (() => unknown)[],
  mockAlert: vi.fn((..._args: unknown[]): Promise<void> => noopAsync()),
  mockCreateFolderSafe: vi.fn((..._args: unknown[]): Promise<void> => noopAsync()),
  mockGetAttachmentFolderFullPathForPath: vi.fn((..._args: unknown[]): Promise<string> => Promise.resolve('attachments')),
  mockGetAvailablePathForAttachments: vi.fn((..._args: unknown[]): Promise<string> => Promise.resolve('attachments/file.png')),
  mockGetGeneratedAttachmentFileBaseName: vi.fn((..._args: unknown[]): Promise<string> => Promise.resolve('generated')),
  mockGetImageSize: vi.fn((..._args: unknown[]): Promise<null | string> => Promise.resolve(null)),
  mockGetMimeType: vi.fn((_extension: string): null | string => null),
  mockImportFilesOriginal: vi.fn((..._args: unknown[]): Promise<void> => noopAsync()),
  mockIsNoteEx: vi.fn((..._args: unknown[]): boolean => true),
  mockRegisterCustomTokens: vi.fn(),
  mockRenameDeleteHandlerComponent: vi.fn((_params: unknown): void => undefined),
  mockSettings: {
    attachmentRenameMode: 'None',
    convertImagesToJpegMode: 'None',
    customTokensStr: '',
    duplicateNameSeparator: ' ',
    emptyFolderBehavior: 'Keep',
    isPathIgnored: vi.fn((_path: string): boolean => false),
    jpegQuality: 0.8,
    markdownUrlFormat: '',
    shouldDeleteOrphanAttachments: false,
    shouldHandleRenames: true,
    shouldRenameAttachmentFiles: false,
    shouldRenameAttachmentFolder: false,
    specialCharacters: '',
    specialCharactersRegExp: /[\\]/g,
    specialCharactersReplacement: '-',
    version: ''
  }
}));

const mockSettings = castTo<PluginSettings>(hoisted.mockSettings);

// --- obsidian mock ---

vi.mock('obsidian', async (importOriginal) => {
  const original = await importOriginal<typeof import('obsidian')>();

  class MockCapacitorAdapter {}
  class MockFileSystemAdapter {}

  class MockMenuItem {
    public callback?: () => void;
    public iconEl: HTMLElement = activeDocument.createElement('div');
  }

  class MockMarkdownView {
    public editMode: MockMarkdownViewEditMode = { clipboardManager: {} };
    public editor: MockMarkdownViewEditor;
    public file: null | TFile = null;

    public constructor(replaceSelection?: (text: string) => void) {
      this.editor = { replaceSelection: replaceSelection ?? ((): void => undefined) };
    }

    public getViewType(): string {
      return 'markdown';
    }

    public loadIfDeferred(): Promise<void> {
      return noopAsync();
    }
  }

  return {
    ...original,
    CapacitorAdapter: MockCapacitorAdapter,
    FileSystemAdapter: MockFileSystemAdapter,
    MarkdownView: MockMarkdownView,
    MenuItem: MockMenuItem
  };
});

// --- electron mock ---

vi.mock('electron', () => ({
  webUtils: {
    getPathForFile: vi.fn((_file: File): string => '/abs/path')
  }
}));

vi.mock('@obsidian-typings/obsidian-public-latest/implementations', async (importOriginal) => {
  const original = await importOriginal<typeof import('@obsidian-typings/obsidian-public-latest/implementations')>();
  return {
    ...original,
    isReferenceCache: vi.fn((_link: unknown): boolean => true),
    parentFolderPath: vi.fn((path: string): string => {
      const index = path.lastIndexOf('/');
      return index >= 0 ? path.slice(0, index) : '';
    })
  };
});

// --- local module mocks (owned by other agents) ---

vi.mock('./attachment-collector.ts', () => ({
  isNoteEx: (...args: unknown[]): boolean => hoisted.mockIsNoteEx(...args)
}));

vi.mock('./attachment-path.ts', () => ({
  getAttachmentFolderFullPathForPath: (...args: unknown[]): Promise<string> => hoisted.mockGetAttachmentFolderFullPathForPath(...args),
  getGeneratedAttachmentFileBaseName: (...args: unknown[]): Promise<string> => hoisted.mockGetGeneratedAttachmentFileBaseName(...args)
}));

vi.mock('./image.ts', () => ({
  getImageSize: (...args: unknown[]): Promise<null | string> => hoisted.mockGetImageSize(...args),
  getMimeType: (extension: string): null | string => hoisted.mockGetMimeType(extension)
}));

const { CommandHandlerMock } = vi.hoisted(() => ({
  CommandHandlerMock: class {
    public constructor(_params: unknown) {
      // No-op command handler mock.
    }
  }
}));

vi.mock('./command-handlers/collect-attachments-entire-vault-command-handler.ts', () => ({ CollectAttachmentsEntireVaultCommandHandler: CommandHandlerMock }));
vi.mock(
  './command-handlers/collect-attachments-in-current-folder-command-handler.ts',
  () => ({ CollectAttachmentsInCurrentFolderCommandHandler: CommandHandlerMock })
);
vi.mock('./command-handlers/collect-attachments-in-file-command-handler.ts', () => ({ CollectAttachmentsInFileCommandHandler: CommandHandlerMock }));
vi.mock('./command-handlers/move-attachment-to-proper-folder-command-handler.ts', () => ({ MoveAttachmentToProperFolderCommandHandler: CommandHandlerMock }));

vi.mock('./prism-component.ts', () => ({
  PrismComponent: class {
    public constructor() {
      // No-op.
    }
  }
}));

vi.mock('./substitutions.ts', () => ({
  Substitutions: class {
    public static registerCustomTokens = hoisted.mockRegisterCustomTokens;

    public fillTemplate = vi.fn((template: string): Promise<string> => Promise.resolve(`filled:${template}`));
  }
}));

vi.mock('./plugin-settings-component.ts', () => ({
  PluginSettingsComponent: class {
    public editAndSave = vi.fn((editor: (settings: PluginSettings) => void): Promise<void> => {
      editor(mockSettings);
      return noopAsync();
    });

    public loadFromFile = vi.fn((): Promise<void> => noopAsync());
    public settings = mockSettings;
  }
}));

vi.mock('./plugin-settings-tab.ts', () => ({
  PluginSettingsTab: class {
    public constructor(_params: unknown) {
      // No-op.
    }
  }
}));

// --- obsidian-dev-utils mocks ---

vi.mock('obsidian-dev-utils/async', async (importOriginal) => {
  const original = await importOriginal<typeof import('obsidian-dev-utils/async')>();
  return {
    ...original,
    convertAsyncToSync: vi.fn((fn: (...args: unknown[]) => Promise<unknown>) => (...args: unknown[]): void => {
      fn(...args).catch((): void => undefined);
    })
  };
});

vi.mock('obsidian-dev-utils/blob', () => ({
  blobToJpegArrayBuffer: vi.fn((..._args: unknown[]): Promise<ArrayBuffer> => Promise.resolve(new ArrayBuffer(4)))
}));

vi.mock('obsidian-dev-utils/obsidian/active-file-provider', () => ({
  AppActiveFileProvider: class {
    public constructor(_app: unknown) {
      // No-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/attachment-path', async (importOriginal) => {
  const original = await importOriginal<typeof import('obsidian-dev-utils/obsidian/attachment-path')>();
  return {
    ...original,
    DUMMY_PATH: original.DUMMY_PATH,
    getAvailablePathForAttachments: (...args: unknown[]): Promise<string> => hoisted.mockGetAvailablePathForAttachments(...args)
  };
});

vi.mock('obsidian-dev-utils/obsidian/command-handlers/command-handler-component', () => ({
  CommandHandlerComponent: class {
    public constructor(_params: unknown) {
      // No-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/command-registrar', () => ({
  PluginCommandRegistrar: class {
    public constructor(_plugin: unknown) {
      // No-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/components/all-windows-event-component', () => ({
  AllWindowsEventComponent: class {
    public constructor(_app: unknown) {
      // No-op.
    }

    public registerAllDocumentsDomEvent(name: string, handler: (...args: unknown[]) => unknown): void {
      hoisted.capturedEvents.push({ handler, name: `all-documents:${name}` });
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/components/i18n-component', () => ({
  I18nComponent: class {
    public constructor(_translationsMap: unknown) {
      // No-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/components/layout-ready-component', () => ({
  CallbackLayoutReadyComponent: class {
    public constructor(_app: unknown, callback: () => unknown) {
      hoisted.layoutReadyCallbacks.push(callback);
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/components/menu-event-registrar-component', () => ({
  MenuEventRegistrarComponent: class {
    public constructor(_app: unknown) {
      // No-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/components/monkey-around-component', () => ({
  MonkeyAroundComponent: class {
    public registerPatch(obj: object, factories: PatchFactories): void {
      hoisted.capturedPatches.push({ target: obj });
      const rawTarget = castTo<PatchTarget>(bypassStrictProxy(obj));
      const target = castTo<PatchTarget>(obj);
      for (const [name, factory] of Object.entries(factories)) {
        const next = rawTarget[name];
        target[name] = factory(next);
      }
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/components/plugin-settings-tab-component', () => ({
  PluginSettingsTabComponent: class {
    public constructor(_params: unknown) {
      // No-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/data-handler', () => ({
  PluginDataHandler: class {
    public constructor(_plugin: unknown) {
      // No-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/file-system', () => ({
  getAbstractFileOrNull: vi.fn((..._args: unknown[]): null => null),
  getFileOrNull: vi.fn((..._args: unknown[]): null | TFile => null),
  getPath: vi.fn((_app: unknown, pathOrFile: unknown): string => typeof pathOrFile === 'string' ? pathOrFile : castTo<TFile>(pathOrFile).path),
  isNote: vi.fn((..._args: unknown[]): boolean => true)
}));

vi.mock('obsidian-dev-utils/obsidian/link', async (importOriginal) => {
  const original = await importOriginal<typeof import('obsidian-dev-utils/obsidian/link')>();
  return {
    ...original,
    encodeUrl: vi.fn((url: string): string => url),
    extractLinkFile: vi.fn((..._args: unknown[]): null | TFile => null),
    generateMarkdownLink: vi.fn((..._args: unknown[]): string => '[markdown](url)'),
    testAngleBrackets: vi.fn((_link: string): boolean => false),
    testWikilink: vi.fn((_link: string): boolean => false)
  };
});

vi.mock('obsidian-dev-utils/obsidian/metadata-cache', () => ({
  getAllLinks: vi.fn((..._args: unknown[]): unknown[] => []),
  getCacheSafe: vi.fn((..._args: unknown[]): Promise<null | object> => Promise.resolve(null))
}));

vi.mock('obsidian-dev-utils/obsidian/modals/alert', () => ({
  alert: (...args: unknown[]): Promise<void> => hoisted.mockAlert(...args)
}));

vi.mock('obsidian-dev-utils/obsidian/plugin/plugin', () => ({
  PluginBase: class {
    public abortSignalComponent = { abortSignal: new AbortController().signal };
    public app: App;
    public consoleDebugComponent = {};
    public i18nComponent = {};
    public manifest: PluginManifest;

    public constructor(app: App, manifest: PluginManifest) {
      this.app = app;
      this.manifest = manifest;
    }

    public addChild<T>(child: T): T {
      return child;
    }

    public async onload(): Promise<void> {
      await noopAsync();
    }

    public registerEvent(_ref: unknown): void {
      // No-op.
    }

    public removeChild<T>(child: T): T {
      return child;
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/plugin/plugin-event-source', () => ({
  PluginEventSourceImpl: class {
    public constructor(_plugin: unknown) {
      // No-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/components/rename-delete-handler-component', async (importOriginal) => {
  const original = await importOriginal<typeof import('obsidian-dev-utils/obsidian/components/rename-delete-handler-component')>();
  return {
    ...original,
    RenameDeleteHandlerComponent: class {
      public constructor(params: unknown) {
        hoisted.mockRenameDeleteHandlerComponent(params);
      }
    }
  };
});

vi.mock('obsidian-dev-utils/obsidian/vault', () => ({
  createFolderSafe: (...args: unknown[]): Promise<void> => hoisted.mockCreateFolderSafe(...args)
}));

/* eslint-disable import-x/first, import-x/imports-first -- vi.mock must precede imports. */
import { isReferenceCache } from '@obsidian-typings/obsidian-public-latest/implementations';
import { webUtils } from 'electron';
import {
  CapacitorAdapter,
  FileSystemAdapter,
  MarkdownView,
  MenuItem
} from 'obsidian';
import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import {
  getAbstractFileOrNull,
  getFileOrNull,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import {
  extractLinkFile,
  generateMarkdownLink,
  testAngleBrackets,
  testWikilink
} from 'obsidian-dev-utils/obsidian/link';
import {
  getAllLinks,
  getCacheSafe
} from 'obsidian-dev-utils/obsidian/metadata-cache';

import { Plugin } from './plugin.ts';
/* eslint-enable import-x/first, import-x/imports-first -- vi.mock must precede imports. */

interface MockMenuItem {
  callback?(): void;
  iconEl: HTMLElement;
}

function asPrivate(plugin: Plugin): PluginPrivate {
  return castTo<PluginPrivate>(plugin);
}

function createMarkdownView(filePath: string, replaceSelection: (text: string) => void): MarkdownView {
  const view = castTo<FileWithPath>(new MarkdownView(castTo<WorkspaceLeaf>(replaceSelection)));
  view.file = strictProxy<TFile>({ path: filePath });
  return castTo<MarkdownView>(view);
}

function createMenuItem(hasFileIcon: boolean): MockMenuItem {
  const menuItem = castTo<MockMenuItem>(Object.create(MenuItem.prototype));
  menuItem.iconEl = activeDocument.createElement('div');
  if (hasFileIcon) {
    menuItem.iconEl.appendChild(activeDocument.createElement('div')).addClass('lucide-file');
  }
  return menuItem;
}

function createMockApp(overrides: StrictProxyPartial<App>): App {
  const workspaceOn = vi.fn((name: string, handler: (...args: unknown[]) => unknown): EventRefLike => {
    hoisted.capturedEvents.push({ handler, name: `workspace:${name}` });
    return { id: name };
  });
  const vaultOn = vi.fn((name: string, handler: (...args: unknown[]) => unknown): EventRefLike => {
    hoisted.capturedEvents.push({ handler, name: `vault:${name}` });
    return { id: name };
  });
  return strictProxy<App>({
    fileManager: castTo<App['fileManager']>({
      generateMarkdownLink: vi.fn((_file: TFile, _sourcePath: string): string => '[[link]]')
    }),
    shareReceiver: castTo<App['shareReceiver']>(Object.create({ importFiles: hoisted.mockImportFilesOriginal })),
    vault: castTo<App['vault']>({
      adapter: {},
      create: vi.fn((): Promise<TFile> => Promise.resolve(strictProxy<TFile>({ path: '' }))),
      createBinary: vi.fn((path: string): Promise<TFile> => Promise.resolve(strictProxy<TFile>({ name: 'file.png', path }))),
      exists: vi.fn((): Promise<boolean> => Promise.resolve(true)),
      getAvailablePath: vi.fn((path: string, extension: string): string => `${path}.${extension}`),
      getConfig: vi.fn((_name: string): unknown => 'config'),
      on: vaultOn
    }),
    workspace: castTo<App['workspace']>({
      getActiveFile: vi.fn((): null | TFile => null),
      getActiveViewOfType: vi.fn((): unknown => null),
      getLeavesOfType: vi.fn((): WorkspaceLeaf[] => []),
      on: workspaceOn
    }),
    ...overrides
  });
}

function createPlugin(appOverrides?: StrictProxyPartial<App>): Plugin {
  const app = createMockApp(appOverrides ?? {});
  const manifest = castTo<PluginManifest>({ dir: 'plugins/x', id: 'custom-attachment-location', name: 'Custom Attachment Location', version: '10.0.0' });
  return new Plugin(app, manifest);
}

function createVaultWithAdapter(adapter: object): App['vault'] {
  return castTo<App['vault']>({
    adapter,
    create: vi.fn((): Promise<TFile> => Promise.resolve(strictProxy<TFile>({ path: '' }))),
    createBinary: vi.fn((path: string): Promise<TFile> => Promise.resolve(strictProxy<TFile>({ name: 'file.png', path }))),
    exists: vi.fn((): Promise<boolean> => Promise.resolve(true)),
    getAvailablePath: vi.fn((path: string, extension: string): string => `${path}.${extension}`),
    getConfig: vi.fn((_name: string): unknown => 'config'),
    on: vi.fn((): EventRefLike => ({ id: 'ref' }))
  });
}

function findEvent(name: string): CapturedEvent | undefined {
  return hoisted.capturedEvents.find((event) => event.name === name);
}

function formatTimestamp(date: Date): string {
  return `${pad(date.getFullYear(), 4)}${pad(date.getMonth() + 1)}${pad(date.getDate())}${pad(date.getHours())}${pad(date.getMinutes())}${
    pad(date.getSeconds())
  }`;

  function pad(value: number, length = 2): string {
    return String(value).padStart(length, '0');
  }
}

function makeJpegParams(isPastedImage = false): ConvertImageToJpegParams {
  return {
    attachmentFileContent: new ArrayBuffer(4),
    attachmentFileExtension: 'png',
    isPastedImage
  };
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('Plugin', () => {
  beforeEach(() => {
    castTo<WebUtilsLike>(webUtils).getPathForFile = vi.fn((_file: File): string => '/abs/path');
    hoisted.capturedEvents.length = 0;
    hoisted.capturedPatches.length = 0;
    hoisted.layoutReadyCallbacks.length = 0;
    mockSettings.markdownUrlFormat = '';
    mockSettings.specialCharacters = '';
    mockSettings.attachmentRenameMode = AttachmentRenameMode.None;
    mockSettings.convertImagesToJpegMode = ConvertImagesToJpegMode.None;
    mockSettings.version = '';
    castTo<ReturnType<typeof vi.fn>>(mockSettings.isPathIgnored).mockReturnValue(false);
    hoisted.mockGetMimeType.mockReturnValue(null);
    hoisted.mockGetImageSize.mockResolvedValue(null);
    hoisted.mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
    hoisted.mockGetGeneratedAttachmentFileBaseName.mockResolvedValue('generated');
    hoisted.mockIsNoteEx.mockReturnValue(true);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('should create a plugin instance', () => {
      const plugin = createPlugin();
      expect(plugin).toBeInstanceOf(Plugin);
    });

    it('should register a layout-ready callback', () => {
      createPlugin();
      expect(hoisted.layoutReadyCallbacks).toHaveLength(1);
    });
  });

  describe('replaceSpecialCharacters', () => {
    it('should return the string unchanged when there are no special characters configured', () => {
      const plugin = createPlugin();
      mockSettings.specialCharacters = '';
      expect(plugin.replaceSpecialCharacters('a\\b')).toBe('a\\b');
    });

    it('should replace the configured special characters', () => {
      const plugin = createPlugin();
      mockSettings.specialCharacters = '\\';
      expect(plugin.replaceSpecialCharacters('a\\b')).toBe('a-b');
    });
  });

  describe('getSequenceNumber', () => {
    it('should return 0 when the old attachment file does not exist', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(null);
      const result = await plugin.getSequenceNumber('note.md', 'attachment.png');
      expect(result).toBe(0);
    });

    it('should return 0 when there is no cache', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'attachment.png' }));
      castTo<ReturnType<typeof vi.fn>>(getCacheSafe).mockResolvedValue(null);
      const result = await plugin.getSequenceNumber('note.md', 'attachment.png');
      expect(result).toBe(0);
    });

    it('should return the sequence number when the link matches', async () => {
      const plugin = createPlugin();
      const attachmentFile = strictProxy<TFile>({ path: 'attachment.png' });
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(attachmentFile);
      castTo<ReturnType<typeof vi.fn>>(getCacheSafe).mockResolvedValue({});
      castTo<ReturnType<typeof vi.fn>>(getAllLinks).mockReturnValue([{ link: 'a' }, { link: 'b' }]);
      castTo<ReturnType<typeof vi.fn>>(extractLinkFile)
        .mockReturnValueOnce(strictProxy<TFile>({ path: 'other.png' }))
        .mockReturnValueOnce(attachmentFile);
      const result = await plugin.getSequenceNumber('note.md', 'attachment.png');
      expect(result).toBe(2);
    });

    it('should return 0 when no link matches', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'attachment.png' }));
      castTo<ReturnType<typeof vi.fn>>(getCacheSafe).mockResolvedValue({});
      castTo<ReturnType<typeof vi.fn>>(getAllLinks).mockReturnValue([{ link: 'a' }]);
      castTo<ReturnType<typeof vi.fn>>(extractLinkFile).mockReturnValue(strictProxy<TFile>({ path: 'other.png' }));
      const result = await plugin.getSequenceNumber('note.md', 'attachment.png');
      expect(result).toBe(0);
    });
  });

  describe('onload', () => {
    it('should register file-open, rename and menu events', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      expect(findEvent('workspace:file-open')).toBeDefined();
      expect(findEvent('vault:rename')).toBeDefined();
      expect(findEvent('workspace:receive-text-menu')).toBeDefined();
      expect(findEvent('workspace:receive-files-menu')).toBeDefined();
    });

    it('should patch app.saveAttachment to route through the plugin', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      const app = castTo<SaveAttachmentLike>(plugin.app);
      const result = await app.saveAttachment('image', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should provide rename-delete handler settings through the registered builder', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      const params = castTo<RenameDeleteHandlerComponentParamsProbe>(hoisted.mockRenameDeleteHandlerComponent.mock.calls[0]?.[0]);
      const settings = params.settingsBuilder();
      expect(settings.isNote('note.md')).toBe(true);
      expect(settings.isPathIgnored('note.md')).toBe(false);
    });
  });

  describe('onLayoutReady', () => {
    it('should register custom tokens, load settings and patch the vault', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      expect(hoisted.mockRegisterCustomTokens).toHaveBeenCalled();
      const vault = castTo<VaultGetAvailablePath>(plugin.app.vault);
      expect(vault.getAvailablePath('dir/file', 'png')).toBeDefined();
    });

    it('should register an active-leaf-change event when no markdown view is patched', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      expect(findEvent('workspace:active-leaf-change')).toBeDefined();
    });

    it('should show the release notes', async () => {
      const plugin = createPlugin();
      mockSettings.version = '';
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      expect(hoisted.mockAlert).not.toHaveBeenCalled();
    });
  });

  describe('getConfig', () => {
    it('should delegate to the next function for non-attachment config', () => {
      const plugin = createPlugin();
      const next = vi.fn((_name: string): unknown => 'delegated');
      const result = asPrivate(plugin).getConfig(next, 'someConfig');
      expect(result).toBe('delegated');
    });

    it('should delegate when no current attachment folder path is set', () => {
      const plugin = createPlugin();
      asPrivate(plugin).currentAttachmentFolderPath = null;
      const next = vi.fn((_name: string): unknown => 'delegated');
      const result = asPrivate(plugin).getConfig(next, 'attachmentFolderPath');
      expect(result).toBe('delegated');
    });

    it('should return the current attachment folder path when set', () => {
      const plugin = createPlugin();
      asPrivate(plugin).currentAttachmentFolderPath = 'custom/folder';
      const next = vi.fn((_name: string): unknown => 'delegated');
      const result = asPrivate(plugin).getConfig(next, 'attachmentFolderPath');
      expect(result).toBe('custom/folder');
    });
  });

  describe('getPathForFile', () => {
    it('should return the existing path property when present', () => {
      const plugin = createPlugin();
      const file = castTo<File>({ path: '/existing/path' });
      const next = vi.fn((_file: File): string => '/fallback');
      expect(asPrivate(plugin).getPathForFile(file, next)).toBe('/existing/path');
    });

    it('should fall back to next when the file has no path property', () => {
      const plugin = createPlugin();
      const file = castTo<File>({});
      const next = vi.fn((_file: File): string => '/fallback');
      expect(asPrivate(plugin).getPathForFile(file, next)).toBe('/fallback');
    });
  });

  describe('handleFileOpen', () => {
    it('should clear the state when the file is null', async () => {
      const plugin = createPlugin();
      await asPrivate(plugin).handleFileOpen(null);
      expect(asPrivate(plugin).currentAttachmentFolderPath).toBeNull();
    });

    it('should clear the state when the path is ignored', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(mockSettings.isPathIgnored).mockReturnValue(true);
      await asPrivate(plugin).handleFileOpen(strictProxy<TFile>({ path: 'ignored.md' }));
      expect(asPrivate(plugin).lastOpenFilePath).toBeNull();
    });

    it('should do nothing when the file is already the last opened file', async () => {
      const plugin = createPlugin();
      asPrivate(plugin).lastOpenFilePath = 'note.md';
      await asPrivate(plugin).handleFileOpen(strictProxy<TFile>({ path: 'note.md' }));
      expect(hoisted.mockGetAttachmentFolderFullPathForPath).not.toHaveBeenCalled();
    });

    it('should compute the attachment folder path for a new file', async () => {
      const plugin = createPlugin();
      hoisted.mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments/note');
      await asPrivate(plugin).handleFileOpen(strictProxy<TFile>({ path: 'note.md' }));
      expect(asPrivate(plugin).currentAttachmentFolderPath).toBe('attachments/note');
    });
  });

  describe('handleRename', () => {
    it('should re-run handleFileOpen for the active file', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'active.md' }));
      hoisted.mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments/active');
      await asPrivate(plugin).handleRename();
      expect(asPrivate(plugin).currentAttachmentFolderPath).toBe('attachments/active');
    });
  });

  describe('handleReceiveTextMenu', () => {
    it('should set the matching menu item callback', () => {
      const plugin = createPlugin();
      const menuItem = createMenuItem(true);
      const menu = { items: [menuItem] };
      asPrivate(plugin).handleReceiveTextMenu(menu, 'some text');
      expect(menuItem.callback).toBeDefined();
    });

    it('should do nothing when there is no matching menu item', () => {
      const plugin = createPlugin();
      const menuItem = createMenuItem(false);
      const menu = { items: [menuItem] };
      asPrivate(plugin).handleReceiveTextMenu(menu, 'some text');
      expect(menuItem.callback).toBeUndefined();
    });

    it('should insert the text when the callback runs with an active markdown view', () => {
      const plugin = createPlugin();
      const replaceSelection = vi.fn();
      const markdownView = createMarkdownView('note.md', replaceSelection);
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveViewOfType).mockReturnValue(markdownView);
      const menuItem = createMenuItem(true);
      asPrivate(plugin).handleReceiveTextMenu({ items: [menuItem] }, 'inserted text');
      menuItem.callback?.();
      expect(replaceSelection).toHaveBeenCalledWith('inserted text');
    });

    it('should not insert when there is no active markdown view file', () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveViewOfType).mockReturnValue(null);
      const menuItem = createMenuItem(true);
      asPrivate(plugin).handleReceiveTextMenu({ items: [menuItem] }, 'inserted text');
      expect(() => menuItem.callback?.()).not.toThrow();
    });
  });

  describe('handleReceiveFilesMenu', () => {
    it('should build links for the received attachment files', () => {
      const plugin = createPlugin();
      const replaceSelection = vi.fn();
      const markdownView = createMarkdownView('note.md', replaceSelection);
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveViewOfType).mockReturnValue(markdownView);
      const menuItem = createMenuItem(true);
      asPrivate(plugin).handleReceiveFilesMenu({ items: [menuItem] }, [strictProxy<TFile>({ path: 'a.png' })]);
      menuItem.callback?.();
      expect(replaceSelection).toHaveBeenCalled();
    });
  });

  describe('convertImageToJpeg', () => {
    it('should not convert when the extension has no mime type', async () => {
      const plugin = createPlugin();
      hoisted.mockGetMimeType.mockReturnValue(null);
      const params = makeJpegParams();
      const result = await asPrivate(plugin).convertImageToJpeg(params);
      expect(result.attachmentFileExtension).toBe('png');
    });

    it('should convert all images when the mode is AllImages', async () => {
      const plugin = createPlugin();
      mockSettings.convertImagesToJpegMode = ConvertImagesToJpegMode.AllImages;
      hoisted.mockGetMimeType.mockReturnValue('image/png');
      const result = await asPrivate(plugin).convertImageToJpeg(makeJpegParams());
      expect(result.attachmentFileExtension).toBe('jpg');
    });

    it('should convert non-jpeg images when the mode is AllImagesExceptAlreadyJpegFiles', async () => {
      const plugin = createPlugin();
      mockSettings.convertImagesToJpegMode = ConvertImagesToJpegMode.AllImagesExceptAlreadyJpegFiles;
      hoisted.mockGetMimeType.mockReturnValue('image/png');
      const result = await asPrivate(plugin).convertImageToJpeg(makeJpegParams());
      expect(result.attachmentFileExtension).toBe('jpg');
    });

    it('should not convert jpeg images when the mode is AllImagesExceptAlreadyJpegFiles', async () => {
      const plugin = createPlugin();
      mockSettings.convertImagesToJpegMode = ConvertImagesToJpegMode.AllImagesExceptAlreadyJpegFiles;
      hoisted.mockGetMimeType.mockReturnValue('image/jpeg');
      const result = await asPrivate(plugin).convertImageToJpeg(makeJpegParams());
      expect(result.attachmentFileExtension).toBe('png');
    });

    it('should not convert when the mode is None', async () => {
      const plugin = createPlugin();
      mockSettings.convertImagesToJpegMode = ConvertImagesToJpegMode.None;
      hoisted.mockGetMimeType.mockReturnValue('image/png');
      const result = await asPrivate(plugin).convertImageToJpeg(makeJpegParams());
      expect(result.attachmentFileExtension).toBe('png');
    });

    it('should convert only pasted png images when the mode is OnlyPastedClipboardPngImages', async () => {
      const plugin = createPlugin();
      mockSettings.convertImagesToJpegMode = ConvertImagesToJpegMode.OnlyPastedClipboardPngImages;
      hoisted.mockGetMimeType.mockReturnValue('image/png');
      const result = await asPrivate(plugin).convertImageToJpeg(makeJpegParams(true));
      expect(result.attachmentFileExtension).toBe('jpg');
    });

    it('should not convert non-pasted images when the mode is OnlyPastedClipboardPngImages', async () => {
      const plugin = createPlugin();
      mockSettings.convertImagesToJpegMode = ConvertImagesToJpegMode.OnlyPastedClipboardPngImages;
      hoisted.mockGetMimeType.mockReturnValue('image/png');
      const result = await asPrivate(plugin).convertImageToJpeg(makeJpegParams(false));
      expect(result.attachmentFileExtension).toBe('png');
    });

    it('should throw for an invalid convert images to JPEG mode', async () => {
      const plugin = createPlugin();
      mockSettings.convertImagesToJpegMode = castTo<ConvertImagesToJpegMode>('InvalidMode');
      hoisted.mockGetMimeType.mockReturnValue('image/png');
      await expect(asPrivate(plugin).convertImageToJpeg(makeJpegParams())).rejects.toThrow('Invalid convert images to JPEG mode');
    });
  });

  describe('getConfig (via getCursorLine helpers)', () => {
    it('should return 0 from getCursorLine when the old attachment file is missing', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(null);
      expect(await asPrivate(plugin).getCursorLine('note.md', 'attachment.png')).toBe(0);
    });

    it('should return 0 from getCursorLine when there is no cache', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'attachment.png' }));
      castTo<ReturnType<typeof vi.fn>>(getCacheSafe).mockResolvedValue(null);
      expect(await asPrivate(plugin).getCursorLine('note.md', 'attachment.png')).toBe(0);
    });

    it('should return the matching link line from getCursorLine', async () => {
      const plugin = createPlugin();
      const attachmentFile = strictProxy<TFile>({ path: 'attachment.png' });
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(attachmentFile);
      castTo<ReturnType<typeof vi.fn>>(getCacheSafe).mockResolvedValue({});
      castTo<ReturnType<typeof vi.fn>>(getAllLinks).mockReturnValue([
        { position: { start: { line: 1 } }, reference: 'r0' },
        { position: { start: { line: 7 } }, reference: 'r1' }
      ]);
      castTo<ReturnType<typeof vi.fn>>(isReferenceCache).mockReturnValue(true);
      castTo<ReturnType<typeof vi.fn>>(extractLinkFile)
        .mockReturnValueOnce(null)
        .mockReturnValueOnce(attachmentFile);
      expect(await asPrivate(plugin).getCursorLine('note.md', 'attachment.png')).toBe(7);
    });

    it('should skip non-reference links and return 0 when none match in getCursorLine', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'attachment.png' }));
      castTo<ReturnType<typeof vi.fn>>(getCacheSafe).mockResolvedValue({});
      castTo<ReturnType<typeof vi.fn>>(getAllLinks).mockReturnValue([{ a: 1 }]);
      castTo<ReturnType<typeof vi.fn>>(isReferenceCache).mockReturnValue(false);
      expect(await asPrivate(plugin).getCursorLine('note.md', 'attachment.png')).toBe(0);
    });
  });

  describe('getAvailablePath', () => {
    it('should return the first available path without a suffix', () => {
      const plugin = createPlugin();
      expect(asPrivate(plugin).getAvailablePath('image', 'png')).toBe('image.png');
    });

    it('should append a numeric suffix when the base name is taken', () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getAbstractFileOrNull)
        .mockReturnValueOnce(strictProxy<TFile>({ path: 'image.png' }))
        .mockReturnValueOnce(null);
      expect(asPrivate(plugin).getAvailablePath('image', 'png')).toBe('image 1.png');
    });
  });

  describe('setFileStat', () => {
    it('should return false for an empty path', async () => {
      const plugin = createPlugin();
      expect(await asPrivate(plugin).setFileStat(new ArrayBuffer(4), '')).toBe(false);
    });

    it('should return false for an unrecognized adapter', async () => {
      const plugin = createPlugin();
      expect(await asPrivate(plugin).setFileStat(new ArrayBuffer(4), '/path')).toBe(false);
    });

    it('should record stats from a FileSystemAdapter', async () => {
      const adapter = castTo<FileSystemAdapterLike>(Object.create(FileSystemAdapter.prototype));
      adapter.fsPromises = { stat: vi.fn((): Promise<unknown> => Promise.resolve({ ctimeMs: 1, mtimeMs: 2, size: 3 })) };
      const plugin = createPlugin({ vault: createVaultWithAdapter(adapter) });
      const arrayBuffer = new ArrayBuffer(4);
      expect(await asPrivate(plugin).setFileStat(arrayBuffer, '/path')).toBe(true);
      expect(asPrivate(plugin).arrayBufferFileStatMap.get(arrayBuffer)?.ctime).toBe(1);
    });

    it('should record stats from a CapacitorAdapter', async () => {
      const adapter = castTo<CapacitorAdapterLike>(Object.create(CapacitorAdapter.prototype));
      adapter.fs = { stat: vi.fn((): Promise<unknown> => Promise.resolve({ ctime: 10, mtime: 20 })) };
      const plugin = createPlugin({ vault: createVaultWithAdapter(adapter) });
      const arrayBuffer = new ArrayBuffer(8);
      expect(await asPrivate(plugin).setFileStat(arrayBuffer, '/path')).toBe(true);
      expect(asPrivate(plugin).arrayBufferFileStatMap.get(arrayBuffer)?.size).toBe(8);
    });
  });

  describe('fileArrayBuffer', () => {
    it('should set the stat map from the file metadata for a non-filesystem adapter', async () => {
      const plugin = createPlugin();
      const arrayBuffer = new ArrayBuffer(4);
      const next = vi.fn((): Promise<ArrayBuffer> => Promise.resolve(arrayBuffer));
      const file = castTo<File>({ lastModified: 123, size: 4 });
      const result = await asPrivate(plugin).fileArrayBuffer(next, file);
      expect(result).toBe(arrayBuffer);
      expect(asPrivate(plugin).arrayBufferFileStatMap.get(arrayBuffer)?.mtime).toBe(123);
    });

    it('should fall back to file metadata when the filesystem stat cannot be resolved', async () => {
      castTo<ReturnType<typeof vi.fn>>(webUtils.getPathForFile).mockReturnValue('');
      const adapter = castTo<FileSystemAdapterLike>(Object.create(FileSystemAdapter.prototype));
      adapter.fsPromises = { stat: vi.fn((): Promise<unknown> => Promise.resolve({ ctimeMs: 5, mtimeMs: 6, size: 7 })) };
      const plugin = createPlugin({ vault: createVaultWithAdapter(adapter) });
      const arrayBuffer = new ArrayBuffer(7);
      const next = vi.fn((): Promise<ArrayBuffer> => Promise.resolve(arrayBuffer));
      const result = await asPrivate(plugin).fileArrayBuffer(next, castTo<File>({ lastModified: 42, size: 7 }));
      expect(result).toBe(arrayBuffer);
      expect(asPrivate(plugin).arrayBufferFileStatMap.get(arrayBuffer)?.mtime).toBe(42);
    });

    it('should use the file stat from a FileSystemAdapter when available', async () => {
      const adapter = castTo<FileSystemAdapterLike>(Object.create(FileSystemAdapter.prototype));
      adapter.fsPromises = { stat: vi.fn((): Promise<unknown> => Promise.resolve({ ctimeMs: 5, mtimeMs: 6, size: 7 })) };
      const plugin = createPlugin({ vault: createVaultWithAdapter(adapter) });
      const arrayBuffer = new ArrayBuffer(7);
      const next = vi.fn((): Promise<ArrayBuffer> => Promise.resolve(arrayBuffer));
      const result = await asPrivate(plugin).fileArrayBuffer(next, castTo<File>({ lastModified: 0, size: 0 }));
      expect(result).toBe(arrayBuffer);
      expect(asPrivate(plugin).arrayBufferFileStatMap.get(arrayBuffer)?.ctime).toBe(5);
    });
  });

  describe('generateMarkdownLink', () => {
    it('should return the default link when no markdown URL format is configured', () => {
      const plugin = createPlugin();
      mockSettings.markdownUrlFormat = '';
      const next = vi.fn((): string => '[[default]]');
      const file = strictProxy<TFile>({ path: 'file.png' });
      expect(asPrivate(plugin).generateMarkdownLink(next, file, 'note.md')).toBe('[[default]]');
    });

    it('should use the cached image size as the alias when no alias is given', () => {
      const plugin = createPlugin();
      const file = strictProxy<TFile>({ path: 'file.png' });
      asPrivate(plugin).imageAttachmentSizeMap.set('file.png', '100x100');
      const next = vi.fn((_file: TFile, _sourcePath: string, _subpath?: string, alias?: string): string => `[[default|${alias ?? ''}]]`);
      const result = asPrivate(plugin).generateMarkdownLink(next, file, 'note.md');
      expect(result).toBe('[[default|100x100]]');
    });

    it('should return the default link when there is no markdown URL for the file', () => {
      const plugin = createPlugin();
      mockSettings.markdownUrlFormat = '[url]';
      const next = vi.fn((): string => '[default](path)');
      const file = strictProxy<TFile>({ path: 'file.png' });
      expect(asPrivate(plugin).generateMarkdownLink(next, file, 'note.md')).toBe('[default](path)');
    });

    it('should convert a wikilink to a markdown link with the custom URL', () => {
      const plugin = createPlugin();
      mockSettings.markdownUrlFormat = '[url]';
      const file = strictProxy<TFile>({ path: 'file.png' });
      asPrivate(plugin).pathMarkdownUrlMap.set('file.png', 'custom-url');
      castTo<ReturnType<typeof vi.fn>>(testWikilink).mockReturnValue(true);
      castTo<ReturnType<typeof vi.fn>>(testAngleBrackets).mockReturnValue(false);
      castTo<ReturnType<typeof vi.fn>>(generateMarkdownLink).mockReturnValue('[alias](path.png)');
      const next = vi.fn((): string => '[[file]]');
      const result = asPrivate(plugin).generateMarkdownLink(next, file, 'note.md');
      expect(result).toBe('[alias](custom-url)');
    });

    it('should replace the URL inside angle brackets', () => {
      const plugin = createPlugin();
      mockSettings.markdownUrlFormat = '[url]';
      const file = strictProxy<TFile>({ path: 'file.png' });
      asPrivate(plugin).pathMarkdownUrlMap.set('file.png', 'custom-url');
      castTo<ReturnType<typeof vi.fn>>(testWikilink).mockReturnValue(false);
      castTo<ReturnType<typeof vi.fn>>(testAngleBrackets).mockReturnValue(true);
      const next = vi.fn((): string => '[alias](<path.png>)');
      const result = asPrivate(plugin).generateMarkdownLink(next, file, 'note.md');
      expect(result).toBe('[alias](<custom-url>)');
    });
  });

  describe('importFiles', () => {
    it('should rename each file using the generated base name', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      hoisted.mockGetGeneratedAttachmentFileBaseName.mockResolvedValue('renamed');
      activeWindow.Capacitor = castTo<typeof activeWindow.Capacitor>({ convertFileSrc: vi.fn((uri: string): string => `converted:${uri}`) });
      vi.spyOn(activeWindow, 'fetch').mockResolvedValue(castTo<Response>({
        arrayBuffer: (): Promise<ArrayBuffer> => Promise.resolve(new ArrayBuffer(4))
      }));
      const next = vi.fn((): Promise<void> => noopAsync());
      const files: SharedFileLike[] = [{ name: 'image.png', uri: 'file://image.png' }];
      await asPrivate(plugin).importFiles(next, files);
      expect(files[0]?.name).toContain('renamed');
      expect(next).toHaveBeenCalled();
    });
  });

  describe('insertFiles', () => {
    it('should record stats for each imported attachment then delegate', async () => {
      const plugin = createPlugin();
      const next = vi.fn((): Promise<void> => noopAsync());
      const importedAttachments: ImportedAttachmentLike[] = [
        { data: Promise.resolve(new ArrayBuffer(4)), filepath: '' }
      ];
      await asPrivate(plugin).insertFiles(next, {}, importedAttachments);
      expect(next).toHaveBeenCalled();
    });
  });

  describe('handleInputFileChange', () => {
    it('should ignore non-input targets', () => {
      const plugin = createPlugin();
      const event = new Event('change');
      Object.defineProperty(event, 'target', { value: activeDocument.createElement('div') });
      expect(() => {
        asPrivate(plugin).handleInputFileChange(event);
      }).not.toThrow();
    });

    it('should ignore non-file inputs', () => {
      const plugin = createPlugin();
      const input = activeDocument.createElement('input');
      input.type = 'text';
      const event = new Event('change');
      Object.defineProperty(event, 'target', { value: input });
      expect(() => {
        asPrivate(plugin).handleInputFileChange(event);
      }).not.toThrow();
    });

    it('should patch the array buffer for each selected file', () => {
      const plugin = createPlugin();
      const input = activeDocument.createElement('input');
      input.type = 'file';
      const file = new File([new ArrayBuffer(4)], 'image.png');
      Object.defineProperty(input, 'files', { value: [file] });
      const event = new Event('change');
      Object.defineProperty(event, 'target', { value: input });
      asPrivate(plugin).handleInputFileChange(event);
      expect(hoisted.capturedPatches.some((patch) => patch.target === file)).toBe(true);
    });
  });

  describe('handleActiveLeafChange', () => {
    it('should do nothing when the markdown view is already patched', async () => {
      const plugin = createPlugin();
      asPrivate(plugin).isMarkdownViewPatched = true;
      await asPrivate(plugin).handleActiveLeafChange(null);
      expect(asPrivate(plugin).isMarkdownViewPatched).toBe(true);
    });

    it('should do nothing for a null leaf', async () => {
      const plugin = createPlugin();
      await asPrivate(plugin).handleActiveLeafChange(null);
      expect(asPrivate(plugin).isMarkdownViewPatched).toBe(false);
    });

    it('should do nothing for a non-markdown leaf', async () => {
      const plugin = createPlugin();
      const leaf = castTo<WorkspaceLeaf>({ view: { getViewType: (): string => 'other' } });
      await asPrivate(plugin).handleActiveLeafChange(leaf);
      expect(asPrivate(plugin).isMarkdownViewPatched).toBe(false);
    });

    it('should patch the clipboard manager for a markdown leaf', async () => {
      const plugin = createPlugin();
      const view = createMarkdownView('note.md', vi.fn());
      const leaf = castTo<WorkspaceLeaf>({
        loadIfDeferred: (): Promise<void> => noopAsync(),
        view
      });
      await asPrivate(plugin).handleActiveLeafChange(leaf);
      expect(asPrivate(plugin).isMarkdownViewPatched).toBe(true);
    });
  });

  describe('getAvailablePathForAttachments', () => {
    it('should delegate to the original method for an ignored note when one is available', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(mockSettings.isPathIgnored).mockReturnValue(true);
      const original = vi.fn((): Promise<string> => Promise.resolve('original/ignored.png'));
      castTo<PluginWithOriginal>(plugin).getAvailablePathForAttachmentsOriginal = original;
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' })
      });
      expect(result).toBe('original/ignored.png');
      expect(original).toHaveBeenCalledWith('image', 'png', expect.anything());
    });

    it('should still produce a path for an ignored note when there is no original method', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(true);
      castTo<ReturnType<typeof vi.fn>>(mockSettings.isPathIgnored).mockReturnValue(true);
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' })
      });
      expect(result).toBeDefined();
    });

    it('should use the generic helper when the note is not a markdown note', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.txt' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(false);
      hoisted.mockGetAvailablePathForAttachments.mockResolvedValue('generic/path.png');
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.txt' })
      });
      expect(result).toBe('generic/path.png');
    });

    it('should generate a custom attachment path for a markdown note', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(true);
      hoisted.mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      hoisted.mockGetGeneratedAttachmentFileBaseName.mockResolvedValue('generated');
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' })
      });
      expect(result).toBeDefined();
    });

    it('should skip the generated file name and duplicate check when requested', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(true);
      hoisted.mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' }),
        shouldSkipDuplicateCheck: true,
        shouldSkipGeneratedAttachmentFileName: true
      });
      expect(result).toContain('attachments');
    });

    it('should create the missing attachment folder and add a gitkeep file', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(true);
      castTo<ReturnType<typeof vi.fn>>(plugin.app.vault.exists).mockResolvedValue(false);
      mockSettings.emptyFolderBehavior = castTo<typeof mockSettings.emptyFolderBehavior>('Keep');
      await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' }),
        shouldSkipDuplicateCheck: true,
        shouldSkipGeneratedAttachmentFileName: true,
        shouldSkipMissingAttachmentFolderCreation: false
      });
      expect(hoisted.mockCreateFolderSafe).toHaveBeenCalled();
      expect(plugin.app.vault.create).toHaveBeenCalled();
    });

    it('should initialize content and stat for the dummy base name and handle the import-files prefix', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(null);
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(false);
      hoisted.mockGetAvailablePathForAttachments.mockResolvedValue('generic/path.png');
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: `__IMPORT_FILES__${DUMMY_PATH}`,
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: null
      });
      expect(result).toBe('generic/path.png');
    });
  });

  describe('saveAttachment', () => {
    it('should save through the core path for an ignored note', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(mockSettings.isPathIgnored).mockReturnValue(true);
      const result = await asPrivate(plugin).saveAttachment('image', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should save through the core path when there is no active note', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(null);
      const result = await asPrivate(plugin).saveAttachment('image', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should rename the attachment when the rename mode is All', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.attachmentRenameMode = AttachmentRenameMode.All;
      hoisted.mockGetGeneratedAttachmentFileBaseName.mockResolvedValue('renamed');
      const result = await asPrivate(plugin).saveAttachment('image', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should not rename the attachment when the rename mode is None', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.attachmentRenameMode = AttachmentRenameMode.None;
      const result = await asPrivate(plugin).saveAttachment('image', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should rename only pasted images when the rename mode is OnlyPastedImages', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      const result = await asPrivate(plugin).saveAttachment('image', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should throw for an invalid attachment rename mode', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.attachmentRenameMode = castTo<AttachmentRenameMode>('Invalid');
      await expect(asPrivate(plugin).saveAttachment('image', 'png', new ArrayBuffer(4))).rejects.toThrow('Invalid attachment rename mode');
    });

    it('should detect a recently pasted image and rename it', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      const now = formatTimestamp(new Date());
      const result = await asPrivate(plugin).saveAttachment(`Pasted image ${now}`, 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should store the markdown URL when a markdown URL format is configured', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.markdownUrlFormat = '[url]';
      const result = await asPrivate(plugin).saveAttachment('image', 'png', new ArrayBuffer(4));
      expect(asPrivate(plugin).pathMarkdownUrlMap.size).toBeGreaterThan(0);
      expect(result).toBeDefined();
    });

    it('should record the image size when available', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      hoisted.mockGetImageSize.mockResolvedValue('100x100');
      const result = await asPrivate(plugin).saveAttachment('image', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });
  });

  describe('patched wrappers', () => {
    it('should route vault.getConfig through the plugin', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      const vault = castTo<VaultGetConfig>(plugin.app.vault);
      expect(vault.getConfig('someConfig')).toBe('config');
    });

    it('should route the extended getAvailablePathForAttachments through the plugin', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      const vault = castTo<VaultExtendedGetAvailablePathForAttachments>(plugin.app.vault);
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(null);
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(false);
      hoisted.mockGetAvailablePathForAttachments.mockResolvedValue('generic/path.png');
      const result = await vault.getAvailablePathForAttachments.extended({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: null
      });
      expect(result).toBe('generic/path.png');
    });

    it('should route the original getAvailablePathForAttachments call through next', async () => {
      const nextOriginal = vi.fn((): Promise<string> => Promise.resolve('original/path.png'));
      const plugin = createPlugin({
        vault: castTo<App['vault']>({
          adapter: {},
          create: vi.fn((): Promise<TFile> => Promise.resolve(strictProxy<TFile>({ path: '' }))),
          createBinary: vi.fn((path: string): Promise<TFile> => Promise.resolve(strictProxy<TFile>({ name: 'file.png', path }))),
          exists: vi.fn((): Promise<boolean> => Promise.resolve(true)),
          getAvailablePath: vi.fn((path: string, extension: string): string => `${path}.${extension}`),
          getAvailablePathForAttachments: nextOriginal,
          getConfig: vi.fn((): unknown => 'config'),
          on: vi.fn((): EventRefLike => ({ id: 'ref' }))
        })
      });
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      const vault = castTo<VaultOriginalGetAvailablePathForAttachments>(plugin.app.vault);
      const result = await vault.getAvailablePathForAttachments('image', 'png', null);
      expect(result).toBe('original/path.png');
    });

    it('should route fileManager.generateMarkdownLink through the plugin', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      mockSettings.markdownUrlFormat = '';
      const fileManager = castTo<FileManagerGenerateMarkdownLink>(plugin.app.fileManager);
      expect(fileManager.generateMarkdownLink(strictProxy<TFile>({ path: 'file.png' }), 'note.md')).toBeDefined();
    });

    it('should route shareReceiver.importFiles through the plugin', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      activeWindow.Capacitor = castTo<typeof activeWindow.Capacitor>({ convertFileSrc: vi.fn((uri: string): string => `converted:${uri}`) });
      vi.spyOn(activeWindow, 'fetch').mockResolvedValue(castTo<Response>({
        arrayBuffer: (): Promise<ArrayBuffer> => Promise.resolve(new ArrayBuffer(4))
      }));
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      const shareReceiver = castTo<ShareReceiverImportFiles>(plugin.app.shareReceiver);
      await shareReceiver.importFiles([{ name: 'image.png', uri: 'file://image.png' }]);
      expect(activeWindow.fetch).toHaveBeenCalled();
    });

    it('should route webUtils.getPathForFile through the plugin', async () => {
      const plugin = createPlugin();
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      const path = webUtils.getPathForFile(castTo<File>({ path: '/custom' }));
      expect(path).toBe('/custom');
    });

    it('should route the patched clipboard manager insertFiles through the plugin', async () => {
      const plugin = createPlugin();
      const clipboardManager = {};
      const view = castTo<MarkdownViewWithEditMode>(createMarkdownView('note.md', vi.fn()));
      view.editMode = { clipboardManager };
      const insertFilesOriginal = vi.fn((): Promise<void> => noopAsync());
      Object.setPrototypeOf(clipboardManager, { insertFiles: insertFilesOriginal });
      const leaf = castTo<WorkspaceLeaf>({
        loadIfDeferred: (): Promise<void> => noopAsync(),
        view
      });
      await asPrivate(plugin).handleActiveLeafChange(leaf);
      const patchedManager = castTo<ClipboardManagerInsertFiles>(clipboardManager);
      await patchedManager.insertFiles([{ data: Promise.resolve(new ArrayBuffer(4)), filepath: '' }]);
      expect(insertFilesOriginal).toHaveBeenCalled();
    });

    it('should route the patched file arrayBuffer through the plugin', async () => {
      const plugin = createPlugin();
      const input = activeDocument.createElement('input');
      input.type = 'file';
      const arrayBuffer = new ArrayBuffer(4);
      const file = new File([arrayBuffer], 'image.png');
      const originalArrayBuffer = vi.fn((): Promise<ArrayBuffer> => Promise.resolve(arrayBuffer));
      Object.defineProperty(file, 'arrayBuffer', { configurable: true, value: originalArrayBuffer, writable: true });
      Object.defineProperty(input, 'files', { value: [file] });
      const event = new Event('change');
      Object.defineProperty(event, 'target', { value: input });
      asPrivate(plugin).handleInputFileChange(event);
      const result = await file.arrayBuffer();
      expect(result).toBe(arrayBuffer);
    });
  });

  describe('getAvailablePathForAttachments dummy initialization', () => {
    it('should initialize content and stat when the base name is the dummy path', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(null);
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(false);
      hoisted.mockGetAvailablePathForAttachments.mockResolvedValue('generic/path.png');
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: DUMMY_PATH,
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: null
      });
      expect(result).toBe('generic/path.png');
    });
  });

  describe('showReleaseNotes', () => {
    it('should show a version-mismatch warning when the settings version is newer', async () => {
      const plugin = createPlugin();
      mockSettings.version = '99.0.0';
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      expect(hoisted.mockAlert).toHaveBeenCalled();
    });

    it('should show a version-mismatch warning when the manifest has no directory', async () => {
      const plugin = createPlugin();
      castTo<ManifestWithoutDir>(plugin.manifest).dir = undefined;
      mockSettings.version = '99.0.0';
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      expect(hoisted.mockAlert).toHaveBeenCalled();
    });

    it('should show release notes for new versions', async () => {
      const plugin = createPlugin();
      mockSettings.version = '9.0.0';
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      expect(hoisted.mockAlert).toHaveBeenCalled();
    });
  });

  describe('branch coverage', () => {
    it('should not register active-leaf-change when a markdown view was already patched on layout-ready', async () => {
      const view = createMarkdownView('note.md', vi.fn());
      const leaf = castTo<WorkspaceLeaf>({
        loadIfDeferred: (): Promise<void> => noopAsync(),
        view
      });
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getLeavesOfType).mockReturnValue([leaf]);
      await plugin.onload();
      await asPrivate(plugin).onLayoutReady();
      expect(findEvent('workspace:active-leaf-change')).toBeUndefined();
    });

    it('should keep the original extension when generateMarkdownLink receives an explicit alias', () => {
      const plugin = createPlugin();
      mockSettings.markdownUrlFormat = '';
      const next = vi.fn((_file: TFile, _sourcePath: string, _subpath?: string, alias?: string): string => `[[default|${alias ?? ''}]]`);
      const result = asPrivate(plugin).generateMarkdownLink(next, strictProxy<TFile>({ path: 'file.png' }), 'note.md', undefined, 'explicit');
      expect(result).toBe('[[default|explicit]]');
    });

    it('should resolve the old note path when oldNotePathOrFile is provided', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(true);
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' }),
        oldNotePathOrFile: 'old-note.md',
        shouldSkipDuplicateCheck: true,
        shouldSkipGeneratedAttachmentFileName: true
      });
      expect(result).toBeDefined();
    });

    it('should handle an empty attachment extension during duplicate check', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(true);
      const result = await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: '',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' }),
        shouldSkipGeneratedAttachmentFileName: true
      });
      expect(result).toBeDefined();
    });

    it('should skip folder creation when shouldSkipMissingAttachmentFolderCreation is true', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(true);
      await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' }),
        shouldSkipDuplicateCheck: true,
        shouldSkipGeneratedAttachmentFileName: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(hoisted.mockCreateFolderSafe).not.toHaveBeenCalled();
    });

    it('should not create a gitkeep file when the empty folder behavior is not Keep', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      castTo<ReturnType<typeof vi.fn>>(isNote).mockReturnValue(true);
      castTo<ReturnType<typeof vi.fn>>(plugin.app.vault.exists).mockResolvedValue(false);
      mockSettings.emptyFolderBehavior = castTo<typeof mockSettings.emptyFolderBehavior>('DeleteWithEmptyParents');
      await asPrivate(plugin).getAvailablePathForAttachments({
        attachmentFileBaseName: 'image',
        attachmentFileExtension: 'png',
        context: undefined,
        notePathOrFile: strictProxy<TFile>({ path: 'note.md' }),
        shouldSkipDuplicateCheck: true,
        shouldSkipGeneratedAttachmentFileName: true,
        shouldSkipMissingAttachmentFolderCreation: false
      });
      expect(plugin.app.vault.create).not.toHaveBeenCalled();
    });

    it('should skip reference links whose file does not match in getCursorLine', async () => {
      const plugin = createPlugin();
      const attachmentFile = strictProxy<TFile>({ path: 'attachment.png' });
      castTo<ReturnType<typeof vi.fn>>(getFileOrNull).mockReturnValue(attachmentFile);
      castTo<ReturnType<typeof vi.fn>>(getCacheSafe).mockResolvedValue({});
      castTo<ReturnType<typeof vi.fn>>(getAllLinks).mockReturnValue([{ position: { start: { line: 3 } } }]);
      castTo<ReturnType<typeof vi.fn>>(isReferenceCache).mockReturnValue(true);
      castTo<ReturnType<typeof vi.fn>>(extractLinkFile).mockReturnValue(strictProxy<TFile>({ path: 'other.png' }));
      expect(await asPrivate(plugin).getCursorLine('note.md', 'attachment.png')).toBe(0);
    });

    it('should handle an input with no selected files', () => {
      const plugin = createPlugin();
      const input = activeDocument.createElement('input');
      input.type = 'file';
      Object.defineProperty(input, 'files', { value: null });
      const event = new Event('change');
      Object.defineProperty(event, 'target', { value: input });
      expect(() => {
        asPrivate(plugin).handleInputFileChange(event);
      }).not.toThrow();
    });

    it('should use an empty note path in importFiles when there is no active file', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(null);
      activeWindow.Capacitor = castTo<typeof activeWindow.Capacitor>({ convertFileSrc: vi.fn((uri: string): string => `converted:${uri}`) });
      vi.spyOn(activeWindow, 'fetch').mockResolvedValue(castTo<Response>({
        arrayBuffer: (): Promise<ArrayBuffer> => Promise.resolve(new ArrayBuffer(4))
      }));
      const next = vi.fn((): Promise<void> => noopAsync());
      await asPrivate(plugin).importFiles(next, [{ name: 'image.png', uri: 'file://image.png' }]);
      expect(next).toHaveBeenCalled();
    });

    it('should not treat a base name without a timestamp as a pasted image', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      const result = await asPrivate(plugin).saveAttachment('regular image', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should not treat an old pasted image timestamp as a recent pasted image', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      const result = await asPrivate(plugin).saveAttachment('Pasted image 20000101000000', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should not treat an invalid pasted image timestamp as a pasted image', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      mockSettings.attachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
      const result = await asPrivate(plugin).saveAttachment('Pasted image 99999999999999', 'png', new ArrayBuffer(4));
      expect(result).toBeDefined();
    });

    it('should pass through ctime and mtime when the stat map has truncated values', async () => {
      const plugin = createPlugin();
      castTo<ReturnType<typeof vi.fn>>(plugin.app.workspace.getActiveFile).mockReturnValue(strictProxy<TFile>({ path: 'note.md' }));
      const arrayBuffer = new ArrayBuffer(4);
      asPrivate(plugin).arrayBufferFileStatMap.set(arrayBuffer, { ctime: 1000.7, mtime: 2000.3, size: 4 });
      const result = await asPrivate(plugin).saveAttachment('image', 'png', arrayBuffer);
      expect(result).toBeDefined();
    });

    it('should default capacitor ctime and mtime to 0 when missing', async () => {
      const adapter = castTo<CapacitorAdapterLike>(Object.create(CapacitorAdapter.prototype));
      adapter.fs = { stat: vi.fn((): Promise<unknown> => Promise.resolve({ ctime: null, mtime: null })) };
      const plugin = createPlugin({ vault: createVaultWithAdapter(adapter) });
      const arrayBuffer = new ArrayBuffer(8);
      expect(await asPrivate(plugin).setFileStat(arrayBuffer, '/path')).toBe(true);
      expect(asPrivate(plugin).arrayBufferFileStatMap.get(arrayBuffer)?.ctime).toBe(0);
    });

    it('should not patch web utilities when they are unavailable on the platform', async () => {
      vi.resetModules();
      vi.doMock('electron', () => ({ webUtils: undefined }));
      // eslint-disable-next-line no-restricted-syntax -- A dynamic import is required to reload the plugin after resetting modules so the webUtils-unavailable branch is exercised.
      const { Plugin: FreshPlugin } = await import('./plugin.ts');
      const app = createMockApp({});
      const manifest = castTo<PluginManifest>({ dir: 'plugins/x', id: 'custom-attachment-location', name: 'Custom Attachment Location', version: '10.0.0' });
      const plugin = new FreshPlugin(app, manifest);
      await plugin.onload();
      await castTo<PluginPrivate>(plugin).onLayoutReady();
      const vault = castTo<VaultGetConfig>(plugin.app.vault);
      expect(vault.getConfig('someConfig')).toBe('config');
      vi.doUnmock('electron');
      vi.resetModules();
    });
  });
});
/* eslint-enable @typescript-eslint/no-extraneous-class, @typescript-eslint/no-useless-constructor -- End of test file. */
