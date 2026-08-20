import type { CustomArrayDict } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  Reference,
  TAbstractFile,
  TFile,
  TFolder
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';
import type { CachedMetadataEx } from 'obsidian-dev-utils/obsidian/metadata-cache';
import type {
  CanvasReference,
  CanvasTextNodeReference
} from 'obsidian-dev-utils/obsidian/reference';
import type {
  Mock,
  MockInstance
} from 'vitest';

import {
  Notice,
  Vault
} from 'obsidian';
import { abortSignalAny } from 'obsidian-dev-utils/abort-controller';
import { noopAsync } from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { getCanvasReferences } from 'obsidian-dev-utils/obsidian/canvas';
import { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import { applyFileChanges } from 'obsidian-dev-utils/obsidian/file-change';
import {
  isCanvasFile,
  isFile,
  isFolder,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  editLinks,
  extractLinkFile,
  updateLink
} from 'obsidian-dev-utils/obsidian/link';
import { loop } from 'obsidian-dev-utils/obsidian/loop';
import {
  getBacklinksForFileSafe,
  getCacheSafe,
  getLinks
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { addToQueue } from 'obsidian-dev-utils/obsidian/queue';
import { ResourceLockComponent } from 'obsidian-dev-utils/obsidian/resource-lock';
import {
  cleanupEmptyFolders,
  copySafe,
  renameSafe
} from 'obsidian-dev-utils/obsidian/vault';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { NetworkImageDownloader } from './network-image-downloader.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';

import { AttachmentCollector } from './attachment-collector.ts';
import { translationsMap } from './i18n/locales/translations-map.ts';
import { selectMode } from './modals/collect-attachment-used-by-multiple-notes-modal.ts';
import { CollectAttachmentUsedByMultipleNotesMode } from './plugin-settings.ts';

interface ApplyFileChangesParamsLike {
  changesProvider: FileChangeLike[];
  pathOrFile: TFile;
}

interface FileChangeLike {
  newContent: string;
  reference: Reference;
}

interface LoopBuildNoticeMessageParamsLike {
  item: TFile;
  iterationString: string;
}

interface LoopOptionsLike {
  buildNoticeMessage(params: LoopBuildNoticeMessageParamsLike): string;
  items: TFile[];
  processItem(item: TFile): Promise<void>;
}

interface QueueParamsLike {
  operationFunction(abortSignal: AbortSignal): Promise<void>;
  operationName: string;
}

interface SettingsLike {
  collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode;
  emptyFolderBehavior: EmptyFolderBehavior;
  getTimeoutInMilliseconds(): number;
  isAttachmentUnitFolder(path: string): boolean;
  isExcludedFromAttachmentCollecting(path: string): boolean;
  isExcludedFromMultipleNotesCheck(path: string): boolean;
  isPathIgnored(path: string): boolean;
  notePriorities: readonly string[];
  shouldSkipCollectingAttachmentsReferencedByRawPath: boolean;
}

vi.mock('obsidian-dev-utils/abort-controller', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/abort-controller')>(),
  abortSignalAny: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/canvas', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/canvas')>(),
  getCanvasReferences: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/file-change', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/file-change')>(),
  applyFileChanges: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/file-system', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/file-system')>(),
  isCanvasFile: vi.fn(),
  isFile: vi.fn(),
  isFolder: vi.fn(),
  isNote: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/link', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/link')>(),
  editLinks: vi.fn(),
  extractLinkFile: vi.fn(),
  updateLink: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/loop', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/loop')>(),
  loop: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/metadata-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/metadata-cache')>(),
  getBacklinksForFileSafe: vi.fn(),
  getCacheSafe: vi.fn(),
  getLinks: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/modals/confirm', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/modals/confirm')>(),
  confirm: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/queue', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/queue')>(),
  addToQueue: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/vault', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/vault')>(),
  cleanupEmptyFolders: vi.fn(),
  copySafe: vi.fn(),
  renameSafe: vi.fn()
}));

vi.mock('./modals/collect-attachment-used-by-multiple-notes-modal.ts', () => ({
  selectMode: vi.fn()
}));

const mockAbortSignalAny = vi.mocked(abortSignalAny);
const mockIsCanvasFile = vi.mocked(isCanvasFile);
const mockIsFile = vi.mocked(isFile);
const mockIsFolder = vi.mocked(isFolder);
const mockIsNote = vi.mocked(isNote);
const mockEditLinks = vi.mocked(editLinks);
const mockExtractLinkFile = vi.mocked(extractLinkFile);
const mockUpdateLink = vi.mocked(updateLink);
const mockLoop = vi.mocked(loop);
const mockGetLinks = vi.mocked(getLinks);
const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);
const mockGetCacheSafe = vi.mocked(getCacheSafe);
const mockConfirm = vi.mocked(confirm);
const mockAddToQueue = vi.mocked(addToQueue);
const mockCleanupEmptyFolders = vi.mocked(cleanupEmptyFolders);
const mockCopySafe = vi.mocked(copySafe);
const mockRenameSafe = vi.mocked(renameSafe);
const mockGetCanvasReferences = vi.mocked(getCanvasReferences);
const mockApplyFileChanges = vi.mocked(applyFileChanges);
const mockSelectMode = vi.mocked(selectMode);

const PLUGIN_NAME = 'Custom Attachment Location';

function createBacklinks(keys: string[]): CustomArrayDict<Reference> {
  return strictProxy<CustomArrayDict<Reference>>({
    keys: () => keys
  });
}

// Canvas references are plain objects (not strict proxies).
// The real `isCanvas*` guards and `referenceToFileChange` can then probe arbitrary properties without throwing.
function createCanvasFileNodeReference(overrides: Partial<CanvasReference> = {}): CanvasReference {
  return {
    isCanvas: true,
    key: 'nodes.0.file',
    link: 'img.png',
    nodeIndex: 0,
    original: 'img.png',
    type: 'file',
    ...overrides
  };
}

function createCanvasTextNodeReference(overrides: Partial<CanvasTextNodeReference> = {}): CanvasTextNodeReference {
  return {
    isCanvas: true,
    key: 'nodes.1.text.0',
    link: 'img.png',
    nodeIndex: 1,
    original: '![[img.png]]',
    // A plain object (not a strict proxy) so equality matchers can probe it without throwing.
    originalReference: castTo<Reference>({ link: 'img.png', original: '![[img.png]]' }),
    type: 'text',
    ...overrides
  };
}

function createFile(path: string, isDeleted = false): TFile {
  return strictProxy<TFile>({
    deleted: isDeleted,
    extension: path.split('.').at(-1) ?? '',
    name: path.split('/').at(-1) ?? '',
    path,
    stat: strictProxy<TFile['stat']>({ ctime: 0, mtime: 0, size: 0 })
  });
}

function createReference(overrides: Partial<Reference> = {}): Reference {
  return strictProxy<Reference>({
    link: 'img.png',
    original: '![[img.png]]',
    ...overrides
  });
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('AttachmentCollector', () => {
  let abortSignalComponent: AbortSignalComponent;
  let app: App;
  let attachmentPathManager: AttachmentPathManager;
  let collector: AttachmentCollector;
  let consoleDebug: Mock<(message: string, ...$arguments: unknown[]) => void>;
  let consoleDebugComponent: ConsoleDebugComponent;
  let errorSpy: MockInstance<typeof console.error>;
  let getProperAttachmentPath: Mock<AttachmentPathManager['getProperAttachmentPath']>;
  let getSequenceNumberMap: Mock<AttachmentPathManager['getSequenceNumberMap']>;
  let getFileByPath: Mock<(path: string) => null | TFile>;
  let getFileCache: Mock<(file: TFile) => CachedMetadataEx | null>;
  let getFolderByPath: Mock<(path: string) => null | TFolder>;
  let getRoot: Mock<() => TFolder>;
  let getMarkdownFiles: Mock<() => TFile[]>;
  let cachedRead: Mock<(file: TFile) => Promise<string>>;
  let networkImageDownloader: NetworkImageDownloader;
  let pluginSettingsComponent: PluginSettingsComponent;
  let readJson: Mock<(path: string) => Promise<null | object>>;
  let settings: SettingsLike;
  let warnSpy: MockInstance<typeof console.warn>;
  let pluginNoticeComponent: PluginNoticeComponent;
  let resourceLockComponent: ResourceLockComponent;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = {
      collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode.Move,
      emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
      getTimeoutInMilliseconds: vi.fn<() => number>().mockReturnValue(1000),
      isAttachmentUnitFolder: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      isExcludedFromAttachmentCollecting: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      isExcludedFromMultipleNotesCheck: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      isPathIgnored: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      notePriorities: [],
      shouldSkipCollectingAttachmentsReferencedByRawPath: false
    };
    getRoot = vi.fn<() => TFolder>().mockReturnValue(strictProxy<TFolder>({ path: '/' }));
    readJson = vi.fn<(path: string) => Promise<null | object>>();
    getMarkdownFiles = vi.fn<() => TFile[]>().mockReturnValue([]);
    cachedRead = vi.fn<(file: TFile) => Promise<string>>().mockResolvedValue('');
    getFolderByPath = vi.fn<(path: string) => null | TFolder>().mockReturnValue(null);
    getFileByPath = vi.fn<(path: string) => null | TFile>().mockImplementation((path) => createFile(path));
    getFileCache = vi.fn<(file: TFile) => CachedMetadataEx | null>().mockReturnValue(null);
    app = strictProxy<App>({
      metadataCache: strictProxy<App['metadataCache']>({
        getFileCache: (file: TFile) => getFileCache(file)
      }),
      vault: strictProxy<App['vault']>({
        cachedRead: (file: TFile) => cachedRead(file),
        getFileByPath: (path: string) => getFileByPath(path),
        getFolderByPath: (path: string) => getFolderByPath(path),
        getMarkdownFiles: () => getMarkdownFiles(),
        getRoot: () => getRoot(),
        readJson: (path: string) => readJson(path)
      })
    });
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      isNoteEx: vi.fn<PluginSettingsComponent['isNoteEx']>().mockReturnValue(false),
      settings: castTo<PluginSettings>(settings)
    });
    getProperAttachmentPath = vi.fn<AttachmentPathManager['getProperAttachmentPath']>().mockResolvedValue('attachments/img.png');
    getSequenceNumberMap = vi.fn<AttachmentPathManager['getSequenceNumberMap']>().mockResolvedValue(new Map());
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getProperAttachmentPath: (params) => getProperAttachmentPath(params),
      getSequenceNumberMap: (noteFilePath) => getSequenceNumberMap(noteFilePath)
    });
    abortSignalComponent = strictProxy<AbortSignalComponent>({
      abortSignal: new AbortController().signal
    });
    consoleDebug = vi.fn<(message: string, ...$arguments: unknown[]) => void>();
    consoleDebugComponent = strictProxy<ConsoleDebugComponent>({
      consoleDebug: (message: string, ...$arguments: unknown[]) => {
        consoleDebug(message, ...$arguments);
      }
    });
    networkImageDownloader = strictProxy<NetworkImageDownloader>({
      downloadNetworkImagesForNote: vi.fn().mockResolvedValue(undefined)
    });
    pluginNoticeComponent = new PluginNoticeComponent({ app, pluginName: PLUGIN_NAME });
    resourceLockComponent = strictProxy<ResourceLockComponent>({});
    collector = new AttachmentCollector({
      abortSignalComponent,
      app,
      attachmentPathManager,
      consoleDebugComponent,
      networkImageDownloader,
      pluginName: PLUGIN_NAME,
      pluginNoticeComponent,
      pluginSettingsComponent,
      resourceLockComponent
    });
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
    errorSpy.mockRestore();
  });

  describe('collectAttachmentsEntireVault', () => {
    it('should enqueue an operation for the vault root', () => {
      collector.collectAttachmentsEntireVault();
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      expect(params.operationName).toBe('Collect attachments in entire vault');
    });

    it('should run the operation against the vault root', async () => {
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockLoop.mockResolvedValue(undefined);
      mockConfirm.mockResolvedValue(true);
      mockIsFile.mockReturnValue(false);
      mockIsFolder.mockReturnValue(false);
      collector.collectAttachmentsEntireVault();
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      await params.operationFunction(new AbortController().signal);
      expect(getRoot).toHaveBeenCalled();
      expect(mockLoop).toHaveBeenCalled();
    });
  });

  describe('collectAttachmentsInAbstractFiles', () => {
    it('should enqueue an operation for the given files', () => {
      const files = [strictProxy<TAbstractFile>({ path: 'a.md' })];
      collector.collectAttachmentsInAbstractFiles(files);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      expect(params.operationName).toBe('Collect attachments in file');
    });
  });

  describe('collectAttachments (via queue operationFunction)', () => {
    let note: TFile;

    async function runSingleFile(noteFile: TFile): Promise<void> {
      mockIsFile.mockReturnValue(true);
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockLoop.mockImplementation(async (options) => {
        await castTo<LoopOptionsLike>(options).processItem(noteFile);
      });
      collector.collectAttachmentsInAbstractFiles([noteFile]);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      await params.operationFunction(new AbortController().signal);
    }

    beforeEach(() => {
      note = createFile('note.md');
      mockIsCanvasFile.mockReturnValue(false);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([]);
      getProperAttachmentPath.mockResolvedValue('attachments/img.png');
    });

    it('should return when there is no cache', async () => {
      mockGetCacheSafe.mockResolvedValue(null);
      await runSingleFile(note);
      expect(mockGetLinks).not.toHaveBeenCalled();
    });

    it('should read links from a canvas file', async () => {
      mockIsCanvasFile.mockReturnValue(true);
      mockGetCanvasReferences.mockResolvedValue([]);
      await runSingleFile(note);
      expect(mockGetCanvasReferences).toHaveBeenCalledWith(app, note);
      expect(mockGetLinks).not.toHaveBeenCalled();
    });

    it('should skip when the attachment cannot be prepared (no link file)', async () => {
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(null);
      await runSingleFile(note);
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
    });

    it('should skip when the link file is a note', async () => {
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('other.md'));
      vi.mocked(pluginSettingsComponent.isNoteEx).mockReturnValue(true);
      await runSingleFile(note);
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
    });

    it('should skip when the attachment was already seen', async () => {
      mockGetLinks.mockReturnValue([createReference(), createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      mockRenameSafe.mockResolvedValue('attachments/img.png');
      await runSingleFile(note);
      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledTimes(1);
    });

    it('should skip when the attachment could not be resolved (deleted)', async () => {
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png', true));
      await runSingleFile(note);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('could not be resolved'));
    });

    it('should skip when the attachment is excluded from collecting', async () => {
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      vi.mocked(settings.isExcludedFromAttachmentCollecting).mockReturnValue(true);
      await runSingleFile(note);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('excluded from attachment collecting'));
    });

    it('should move a single-referenced attachment', async () => {
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      mockRenameSafe.mockResolvedValue('attachments/img.png');
      await runSingleFile(note);
      expect(mockRenameSafe).toHaveBeenCalledWith({
        app,
        newPath: 'attachments/img.png',
        oldPathOrAbstractFile: 'img.png'
      });
    });

    it('should clean up the vacated source folder after moving an attachment', async () => {
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('old-folder/img.png'));
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      mockRenameSafe.mockResolvedValue('attachments/img.png');
      await runSingleFile(note);
      expect(mockCleanupEmptyFolders).toHaveBeenCalledWith({
        app,
        emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
        folderPaths: ['old-folder']
      });
    });

    it('should not rename when the new attachment path is null (single-ref)', async () => {
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      getProperAttachmentPath.mockResolvedValue(null);
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      await runSingleFile(note);
      expect(mockRenameSafe).not.toHaveBeenCalled();
    });

    describe('note priorities', () => {
      beforeEach(() => {
        mockGetLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile('img.png'));
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['drawing.excalidraw.md', 'note.md']));
        getProperAttachmentPath.mockResolvedValue('attachments/img.png');
        mockRenameSafe.mockResolvedValue('attachments/img.png');
      });

      it('should move the attachment into the highest-priority referencing note', async () => {
        // The reporter's scenario: an image shared by a drawing and a markdown note, with markdown
        // Ranked first, belongs to the markdown note.
        settings.notePriorities = ['.md', '.excalidraw.md'];

        await runSingleFile(note);

        expect(getProperAttachmentPath).toHaveBeenLastCalledWith(expect.objectContaining({ noteFilePath: 'note.md' }));
        expect(mockRenameSafe).toHaveBeenCalled();
        expect(mockSelectMode).not.toHaveBeenCalled();
      });

      it('should move it into a note other than the one being collected', async () => {
        // The command runs on `note.md`, but the drawing outranks it, so the image goes to the
        // Drawing's folder. That is the point of the setting, and why it is empty by default.
        settings.notePriorities = ['.excalidraw.md', '.md'];

        await runSingleFile(note);

        expect(getProperAttachmentPath).toHaveBeenLastCalledWith(expect.objectContaining({ noteFilePath: 'drawing.excalidraw.md' }));
      });

      it('should rank a note by a frontmatter property', async () => {
        settings.notePriorities = ['property:excalidraw-plugin'];
        getFileCache.mockImplementation((file) =>
          file.path === 'drawing.excalidraw.md'
            ? castTo<CachedMetadataEx>({ frontmatter: { 'excalidraw-plugin': 'parsed' } })
            : null
        );

        await runSingleFile(note);

        expect(getProperAttachmentPath).toHaveBeenLastCalledWith(expect.objectContaining({ noteFilePath: 'drawing.excalidraw.md' }));
      });

      it('should fall back to the mode when the priority list is empty', async () => {
        settings.notePriorities = [];
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;

        await runSingleFile(note);

        expect(mockRenameSafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
      });

      it('should fall back to the mode when several notes tie on the best entry', async () => {
        // Two notes of equal priority is the ambiguity the mode setting already exists for, so the
        // Priority list must not silently pick one of them.
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['a.md', 'b.md']));
        settings.notePriorities = ['.md'];
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;

        await runSingleFile(note);

        expect(mockRenameSafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
      });

      it('should fall back to the mode when no note matches any entry', async () => {
        settings.notePriorities = ['.canvas'];
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;

        await runSingleFile(note);

        expect(mockRenameSafe).not.toHaveBeenCalled();
      });

      it('should fall back to the mode when the winner yields no destination', async () => {
        settings.notePriorities = ['.excalidraw.md'];
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;
        // First call plans the move from the collected note, the recompute for the winner returns null.
        getProperAttachmentPath.mockResolvedValueOnce('attachments/img.png').mockResolvedValueOnce(null);

        await runSingleFile(note);

        expect(mockRenameSafe).not.toHaveBeenCalled();
      });

      it('should fall back to the mode when the attachment file cannot be resolved', async () => {
        settings.notePriorities = ['.excalidraw.md'];
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;
        getFileByPath.mockReturnValue(null);

        await runSingleFile(note);

        expect(mockRenameSafe).not.toHaveBeenCalled();
      });

      it('should leave a singly-referenced attachment alone', async () => {
        settings.notePriorities = ['.md'];
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));

        await runSingleFile(note);

        expect(getProperAttachmentPath).toHaveBeenLastCalledWith(expect.objectContaining({ noteFilePath: 'note.md' }));
        expect(mockRenameSafe).toHaveBeenCalledTimes(1);
      });
    });

    describe('attachment unit folders', () => {
      const UNIT_FOLDER_PATH = 'old-folder/page_files';

      beforeEach(() => {
        vi.mocked(settings.isAttachmentUnitFolder).mockImplementation((path) => path === UNIT_FOLDER_PATH);
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
        getProperAttachmentPath.mockResolvedValue('attachments/img.png');
      });

      it('should move the whole folder instead of the single linked file', async () => {
        // The folder lands in the note's attachment folder under its own name, so the tree's internal
        // Shape - and every relative link inside it - survives.
        const unitFolder = strictProxy<TFolder>({ path: UNIT_FOLDER_PATH });
        getFolderByPath.mockReturnValue(unitFolder);
        mockGetLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile(`${UNIT_FOLDER_PATH}/img/logo.png`));
        mockRenameSafe.mockResolvedValue('attachments/page_files');

        await runSingleFile(note);

        expect(mockRenameSafe).toHaveBeenCalledWith({
          app,
          newPath: 'attachments/page_files',
          oldPathOrAbstractFile: unitFolder
        });
      });

      it('should skip a second link that the first link already carried away inside the folder', async () => {
        // The link snapshot still names the old path, so without this the file reads as unresolvable
        // And would be reported as a broken link rather than as work already done.
        getFolderByPath.mockReturnValue(strictProxy<TFolder>({ path: UNIT_FOLDER_PATH }));
        mockGetLinks.mockReturnValue([createReference(), createReference()]);
        mockExtractLinkFile
          .mockReturnValueOnce(createFile(`${UNIT_FOLDER_PATH}/first.png`))
          .mockReturnValueOnce(createFile(`${UNIT_FOLDER_PATH}/second.png`));
        mockRenameSafe.mockResolvedValue('attachments/page_files');

        await runSingleFile(note);

        expect(mockRenameSafe).toHaveBeenCalledTimes(1);
      });

      it('should still move a later attachment that sits outside the folder already carried away', async () => {
        getFolderByPath.mockReturnValue(strictProxy<TFolder>({ path: UNIT_FOLDER_PATH }));
        mockGetLinks.mockReturnValue([createReference(), createReference()]);
        mockExtractLinkFile
          .mockReturnValueOnce(createFile(`${UNIT_FOLDER_PATH}/inside.png`))
          .mockReturnValueOnce(createFile('elsewhere/outside.png'));
        mockRenameSafe.mockResolvedValue('attachments/whatever');

        await runSingleFile(note);

        expect(mockRenameSafe).toHaveBeenCalledTimes(2);
        expect(mockRenameSafe).toHaveBeenLastCalledWith({
          app,
          newPath: 'attachments/img.png',
          oldPathOrAbstractFile: 'elsewhere/outside.png'
        });
      });

      it('should warn and move nothing when the folder cannot be resolved', async () => {
        getFolderByPath.mockReturnValue(null);
        mockGetLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile(`${UNIT_FOLDER_PATH}/img.png`));

        await runSingleFile(note);

        expect(mockRenameSafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining(`attachment unit folder ${UNIT_FOLDER_PATH}`));
      });

      it('should still move a single file that belongs to no unit folder', async () => {
        mockGetLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile('old-folder/img.png'));
        mockRenameSafe.mockResolvedValue('attachments/img.png');

        await runSingleFile(note);

        expect(mockRenameSafe).toHaveBeenCalledWith({
          app,
          newPath: 'attachments/img.png',
          oldPathOrAbstractFile: 'old-folder/img.png'
        });
      });

      it('should skip rather than copy a unit-folder attachment referenced by multiple notes', async () => {
        // Copying the lone file out of the folder produces exactly the broken attachment the unit
        // Designation exists to prevent.
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        getFolderByPath.mockReturnValue(strictProxy<TFolder>({ path: UNIT_FOLDER_PATH }));
        mockGetLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile(`${UNIT_FOLDER_PATH}/img.png`));
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));

        await runSingleFile(note);

        expect(mockCopySafe).not.toHaveBeenCalled();
        expect(mockRenameSafe).not.toHaveBeenCalled();
      });
    });

    describe('multiple backlinks', () => {
      beforeEach(() => {
        mockGetLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile('img.png'));
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      });

      it('should cancel and abort in Cancel mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
        await runSingleFile(note);
        expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
        expect(mockSelectMode).toHaveBeenCalledWith({ app, attachmentPath: 'img.png', backlinks: ['note.md', 'other.md'], isCancelMode: true });
      });

      it('should not re-invoke selectMode in Cancel mode when the setting is not Cancel', async () => {
        // Setting is Prompt; selectMode resolves to Cancel. The recursive apply then logs the
        // Cancel error but does NOT call selectMode again, since the setting itself is not Cancel.
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Prompt;
        mockSelectMode.mockResolvedValue({
          mode: CollectAttachmentUsedByMultipleNotesMode.Cancel,
          shouldUseSameActionForOtherProblematicAttachments: false
        });
        await runSingleFile(note);
        expect(mockSelectMode).toHaveBeenCalledTimes(1);
        expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
      });

      it('should copy and rewrite links in Copy mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        mockCopySafe.mockResolvedValue('attachments/img.png');
        let matchingResult: unknown;
        let nonMatchingResult: unknown;
        mockEditLinks.mockImplementation(async ({ linkConverter }) => {
          matchingResult = await linkConverter(createReference({ link: 'img.png' }));
          nonMatchingResult = await linkConverter(createReference({ link: 'other.png' }));
        });
        mockExtractLinkFile.mockImplementation(({ link }) => createFile(link.link === 'other.png' ? 'other.png' : 'img.png'));
        mockUpdateLink.mockReturnValue('![](attachments/img.png)');
        await runSingleFile(note);
        expect(mockCopySafe).toHaveBeenCalledWith({
          app,
          newPath: 'attachments/img.png',
          oldPathOrFile: 'img.png'
        });
        expect(matchingResult).toBe('![](attachments/img.png)');
        expect(nonMatchingResult).toBeUndefined();
      });

      it('should not record any vacated folder in Copy mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        mockCopySafe.mockResolvedValue('attachments/img.png');
        await runSingleFile(note);
        expect(mockCleanupEmptyFolders).toHaveBeenCalledWith({
          app,
          emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
          folderPaths: []
        });
      });

      it('should skip Copy mode when the new attachment path is null', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        getProperAttachmentPath.mockResolvedValue(null);
        await runSingleFile(note);
        expect(mockCopySafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('already in the destination folder'));
      });

      it('should move in Move mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Move;
        mockRenameSafe.mockResolvedValue('attachments/img.png');
        await runSingleFile(note);
        expect(mockRenameSafe).toHaveBeenCalledWith({
          app,
          newPath: 'attachments/img.png',
          oldPathOrAbstractFile: 'img.png'
        });
      });

      it('should skip Move mode when the new attachment path is null', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Move;
        getProperAttachmentPath.mockResolvedValue(null);
        await runSingleFile(note);
        expect(mockRenameSafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('already in the destination folder'));
      });

      it('should skip in Skip mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;
        await runSingleFile(note);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
        expect(mockRenameSafe).not.toHaveBeenCalled();
      });

      it('should prompt and apply the chosen mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Prompt;
        mockSelectMode.mockResolvedValue({
          mode: CollectAttachmentUsedByMultipleNotesMode.Move,
          shouldUseSameActionForOtherProblematicAttachments: false
        });
        mockRenameSafe.mockResolvedValue('attachments/img.png');
        await runSingleFile(note);
        expect(mockSelectMode).toHaveBeenCalledWith({ app, attachmentPath: 'img.png', backlinks: ['note.md', 'other.md'] });
        expect(mockRenameSafe).toHaveBeenCalled();
      });

      it('should remember the chosen mode for other attachments when requested', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Prompt;
        mockSelectMode.mockResolvedValue({
          mode: CollectAttachmentUsedByMultipleNotesMode.Skip,
          shouldUseSameActionForOtherProblematicAttachments: true
        });
        await runSingleFile(note);
        // Second link in the same note must reuse the remembered Skip mode without re-prompting.
        mockGetLinks.mockReturnValue([createReference({ link: 'a.png' }), createReference({ link: 'b.png' })]);
        mockExtractLinkFile.mockImplementation(({ link }) => createFile(link.link));
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
        mockSelectMode.mockClear();
        await runSingleFile(note);
        expect(mockSelectMode).toHaveBeenCalledTimes(1);
      });

      it('should throw for an unknown mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = castTo<CollectAttachmentUsedByMultipleNotesMode>('Unknown');
        await expect(runSingleFile(note)).rejects.toThrow('Unknown collect attachment used by multiple notes mode');
        expect(mockRenameSafe).not.toHaveBeenCalled();
      });

      it('should use the context mode when present', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Prompt;
        mockSelectMode.mockResolvedValue({
          mode: CollectAttachmentUsedByMultipleNotesMode.Skip,
          shouldUseSameActionForOtherProblematicAttachments: true
        });
        mockGetLinks.mockReturnValue([createReference({ link: 'a.png' }), createReference({ link: 'b.png' })]);
        mockExtractLinkFile.mockImplementation(({ link }) => createFile(link.link));
        await runSingleFile(note);
        // Prompt chosen once, then context mode (Skip) reused for the second link.
        expect(mockSelectMode).toHaveBeenCalledTimes(1);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
      });

      it('should return early on a subsequent link iteration once context becomes aborted', async () => {
        // Two links: the first triggers Cancel (aborting context), so the second link
        // Iteration returns early before requesting its backlinks.
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
        mockGetLinks.mockReturnValue([createReference({ link: 'a.png' }), createReference({ link: 'b.png' })]);
        mockExtractLinkFile.mockImplementation(({ link }) => createFile(link.link));
        await runSingleFile(note);
        expect(mockGetBacklinksForFileSafe).toHaveBeenCalledTimes(1);
      });

      it('should collect normally when the only extra backlink is an excluded note', async () => {
        // Configured Cancel, but the second backlink matches the multiple-notes-check exclusion,
        // So the effective count drops to one and the attachment is moved normally.
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
        vi.mocked(settings.isExcludedFromMultipleNotesCheck).mockImplementation((path) => path === 'other.md');
        mockRenameSafe.mockResolvedValue('attachments/img.png');
        await runSingleFile(note);
        expect(mockSelectMode).not.toHaveBeenCalled();
        expect(errorSpy).not.toHaveBeenCalled();
        expect(mockRenameSafe).toHaveBeenCalledWith({
          app,
          newPath: 'attachments/img.png',
          oldPathOrAbstractFile: 'img.png'
        });
      });

      it('should still handle multiple notes when only one of several backlinks is excluded', async () => {
        // Three backlinks, one is an excluded note; the two real notes still trigger the Cancel handling,
        // And the modal lists only the two real notes.
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md', 'drawing.excalidraw.md']));
        vi.mocked(settings.isExcludedFromMultipleNotesCheck).mockImplementation((path) => path === 'drawing.excalidraw.md');
        await runSingleFile(note);
        expect(mockSelectMode).toHaveBeenCalledWith({ app, attachmentPath: 'img.png', backlinks: ['note.md', 'other.md'], isCancelMode: true });
      });
    });

    it('should show the notice while running and hide it in the finally block', async () => {
      const hideSpy = vi.spyOn(Notice.prototype, 'hide');
      mockGetLinks.mockReturnValue([]);
      await runSingleFile(note);
      expect(hideSpy).toHaveBeenCalled();
      hideSpy.mockRestore();
    });

    describe('raw path safety scan', () => {
      beforeEach(() => {
        mockGetLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile('img.png'));
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
        mockRenameSafe.mockResolvedValue('attachments/img.png');
        settings.shouldSkipCollectingAttachmentsReferencedByRawPath = true;
      });

      it('should not scan when the setting is off', async () => {
        settings.shouldSkipCollectingAttachmentsReferencedByRawPath = false;
        await runSingleFile(note);
        expect(getMarkdownFiles).not.toHaveBeenCalled();
        expect(mockRenameSafe).toHaveBeenCalled();
      });

      it('should skip and report an attachment referenced by a raw path in a non-indexed note', async () => {
        getMarkdownFiles.mockReturnValue([createFile('other.md')]);
        cachedRead.mockResolvedValue('<img src="img.png">');
        const showNoticeSpy = vi.spyOn(pluginNoticeComponent, 'showNotice');
        await runSingleFile(note);
        expect(mockRenameSafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by a raw path'));
        expect(showNoticeSpy.mock.calls.some((call) => typeof call[0] === 'string' && call[0].includes('raw path'))).toBe(true);
        showNoticeSpy.mockRestore();
      });

      it('should collect normally when no non-indexed note references the attachment', async () => {
        getMarkdownFiles.mockReturnValue([createFile('unrelated.md')]);
        cachedRead.mockResolvedValue('no references here');
        await runSingleFile(note);
        expect(cachedRead).toHaveBeenCalled();
        expect(mockRenameSafe).toHaveBeenCalledWith({
          app,
          newPath: 'attachments/img.png',
          oldPathOrAbstractFile: 'img.png'
        });
      });

      it('should ignore notes that reference the attachment via an indexed link', async () => {
        // The note holding the indexed backlink is skipped by the scan, so its own embed does not
        // Count as a raw-path reference and the attachment is still collected.
        getMarkdownFiles.mockReturnValue([createFile('note.md')]);
        cachedRead.mockResolvedValue('![[img.png]]');
        await runSingleFile(note);
        expect(cachedRead).not.toHaveBeenCalled();
        expect(mockRenameSafe).toHaveBeenCalled();
      });
    });

    describe('canvas references', () => {
      beforeEach(() => {
        mockIsCanvasFile.mockReturnValue(true);
        mockExtractLinkFile.mockReturnValue(createFile('img.png'));
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
        mockRenameSafe.mockResolvedValue('attachments/img.png');
        mockCopySafe.mockResolvedValue('attachments/img.png');
        mockUpdateLink.mockReturnValue('![[attachments/img.png]]');
      });

      it('should rewrite a canvas text-node embed after moving the attachment', async () => {
        const textRef = createCanvasTextNodeReference();
        mockGetCanvasReferences.mockResolvedValue([textRef]);
        await runSingleFile(note);
        expect(mockRenameSafe).toHaveBeenCalledWith({
          app,
          newPath: 'attachments/img.png',
          oldPathOrAbstractFile: 'img.png'
        });
        expect(mockUpdateLink).toHaveBeenCalledWith(expect.objectContaining({
          link: textRef.originalReference,
          newTargetPathOrFile: 'attachments/img.png',
          oldTargetPathOrFile: 'img.png'
        }));
        expect(mockApplyFileChanges).toHaveBeenCalledTimes(1);
        const applyParams = castTo<ApplyFileChangesParamsLike>(mockApplyFileChanges.mock.calls[0]?.[0]);
        expect(applyParams.pathOrFile).toBe(note);
        expect(applyParams.changesProvider).toHaveLength(1);
        expect(applyParams.changesProvider[0]?.newContent).toBe('![[attachments/img.png]]');
        expect(applyParams.changesProvider[0]?.reference).toBe(textRef);
      });

      it('should not rewrite a canvas file-node link on move (Obsidian core handles it)', async () => {
        mockGetCanvasReferences.mockResolvedValue([createCanvasFileNodeReference()]);
        await runSingleFile(note);
        expect(mockRenameSafe).toHaveBeenCalled();
        expect(mockApplyFileChanges).not.toHaveBeenCalled();
      });

      it('should rewrite a canvas file-node link when the attachment is copied', async () => {
        const fileRef = createCanvasFileNodeReference();
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
        mockGetCanvasReferences.mockResolvedValue([fileRef]);
        await runSingleFile(note);
        expect(mockCopySafe).toHaveBeenCalled();
        expect(mockApplyFileChanges).toHaveBeenCalledTimes(1);
        const applyParams = castTo<ApplyFileChangesParamsLike>(mockApplyFileChanges.mock.calls[0]?.[0]);
        expect(applyParams.changesProvider).toHaveLength(1);
        // A file-node prop is a raw path, not a formatted embed.
        expect(applyParams.changesProvider[0]?.newContent).toBe('attachments/img.png');
        expect(applyParams.changesProvider[0]?.reference).toBe(fileRef);
      });

      it('should rewrite a canvas text-node embed when the attachment is copied', async () => {
        const textRef = createCanvasTextNodeReference();
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
        mockGetCanvasReferences.mockResolvedValue([textRef]);
        await runSingleFile(note);
        expect(mockCopySafe).toHaveBeenCalled();
        const applyParams = castTo<ApplyFileChangesParamsLike>(mockApplyFileChanges.mock.calls[0]?.[0]);
        expect(applyParams.changesProvider).toHaveLength(1);
        expect(applyParams.changesProvider[0]?.newContent).toBe('![[attachments/img.png]]');
        expect(applyParams.changesProvider[0]?.reference).toBe(textRef);
      });

      it('should rewrite the text embed even when the same attachment is also a file node', async () => {
        const fileRef = createCanvasFileNodeReference();
        const textRef = createCanvasTextNodeReference();
        mockGetCanvasReferences.mockResolvedValue([fileRef, textRef]);
        await runSingleFile(note);
        // The attachment is moved only once (deduplicated), yet both references are handled.
        // The file node is rewritten by Obsidian core; the text embed by our rewrite.
        expect(mockRenameSafe).toHaveBeenCalledTimes(1);
        const applyParams = castTo<ApplyFileChangesParamsLike>(mockApplyFileChanges.mock.calls[0]?.[0]);
        expect(applyParams.changesProvider).toHaveLength(1);
        expect(applyParams.changesProvider[0]?.reference).toBe(textRef);
      });

      it('should not rewrite canvas references when no attachment is moved', async () => {
        mockGetCanvasReferences.mockResolvedValue([createCanvasTextNodeReference()]);
        getProperAttachmentPath.mockResolvedValue(null);
        await runSingleFile(note);
        expect(mockRenameSafe).not.toHaveBeenCalled();
        expect(mockApplyFileChanges).not.toHaveBeenCalled();
      });

      it('should skip a canvas reference that cannot be resolved to a file', async () => {
        mockGetCanvasReferences.mockResolvedValue([createCanvasTextNodeReference()]);
        mockExtractLinkFile.mockReturnValue(null);
        await runSingleFile(note);
        expect(mockApplyFileChanges).not.toHaveBeenCalled();
      });
    });
  });

  describe('collectAttachmentsInAbstractFilesImpl (via queue operationFunction)', () => {
    async function runOperation(abstractFiles: TAbstractFile[]): Promise<void> {
      collector.collectAttachmentsInAbstractFiles(abstractFiles);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      await params.operationFunction(new AbortController().signal);
    }

    beforeEach(() => {
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockLoop.mockResolvedValue(undefined);
    });

    it('should throw when the signal is already aborted', async () => {
      collector.collectAttachmentsInAbstractFiles([]);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      const controller = new AbortController();
      controller.abort();
      await expect(params.operationFunction(controller.signal)).rejects.toThrow();
    });

    it('should notice and return when the single file path is ignored', async () => {
      mockIsFile.mockReturnValue(true);
      vi.mocked(settings.isPathIgnored).mockReturnValue(true);
      await runOperation([createFile('ignored.md')]);
      expect(mockLoop).not.toHaveBeenCalled();
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('note path is ignored'));
    });

    it('should return when confirmation is declined for multiple files', async () => {
      mockIsFile.mockReturnValue(true);
      mockConfirm.mockResolvedValue(false);
      await runOperation([createFile('a.md'), createFile('b.md')]);
      expect(mockLoop).not.toHaveBeenCalled();
    });

    it('should collect notes from files and folders and run the loop', async () => {
      const noteFile = createFile('a.md');
      const folder = strictProxy<TAbstractFile>({ path: 'folder' });
      const childNote = createFile('folder/c.md');
      mockIsFile.mockImplementation((f) => f === noteFile || f === childNote);
      mockIsFolder.mockImplementation((f) => f === folder);
      mockIsNote.mockReturnValue(true);
      mockConfirm.mockResolvedValue(true);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        callback(childNote);
      });
      try {
        await runOperation([noteFile, folder]);
      } finally {
        recurseSpy.mockRestore();
      }
      const loopOptions = castTo<LoopOptionsLike>(mockLoop.mock.calls[0]?.[0]);
      expect(loopOptions.items).toEqual([noteFile, childNote]);
      expect(consoleDebug).toHaveBeenCalledWith(expect.stringContaining('Collect attachments in files'));
    });

    it('should skip a non-note child during folder recursion', async () => {
      const folder = strictProxy<TAbstractFile>({ path: 'folder' });
      const childNonNote = createFile('folder/img.png');
      mockIsFile.mockReturnValue(false);
      mockIsFolder.mockImplementation((f) => f === folder);
      mockIsNote.mockReturnValue(false);
      mockConfirm.mockResolvedValue(true);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        callback(childNonNote);
      });
      try {
        await runOperation([folder]);
      } finally {
        recurseSpy.mockRestore();
      }
      const loopOptions = castTo<LoopOptionsLike>(mockLoop.mock.calls[0]?.[0]);
      expect(loopOptions.items).toEqual([]);
    });

    it('should not collect a single file that is not a note', async () => {
      const fileNote = createFile('a.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(false);
      mockConfirm.mockResolvedValue(true);
      await runOperation([fileNote]);
      const loopOptions = castTo<LoopOptionsLike>(mockLoop.mock.calls[0]?.[0]);
      expect(loopOptions.items).toEqual([]);
    });

    it('should skip an ignored note inside loop processItem', async () => {
      const noteFile = createFile('a.md');
      const otherFile = createFile('b.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockConfirm.mockResolvedValue(true);
      vi.mocked(settings.isPathIgnored).mockImplementation((path: string) => path === 'a.md');
      mockLoop.mockImplementation(async (options) => {
        await castTo<LoopOptionsLike>(options).processItem(noteFile);
      });
      await runOperation([noteFile, otherFile]);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('note path is ignored'));
      expect(mockGetCacheSafe).not.toHaveBeenCalled();
    });

    it('should abort the controller when the context becomes aborted in processItem', async () => {
      const noteFile = createFile('a.md');
      mockIsFile.mockReturnValue(true);
      mockIsCanvasFile.mockReturnValue(false);
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      getProperAttachmentPath.mockResolvedValue('attachments/img.png');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
      mockLoop.mockImplementation(async (options) => {
        await castTo<LoopOptionsLike>(options).processItem(noteFile);
      });
      await runOperation([noteFile]);
      expect(errorSpy).toHaveBeenCalled();
    });

    it('should return early for a later note once the shared context is aborted', async () => {
      // The first note triggers Cancel (aborting the shared context); the second note then
      // Enters collectAttachments with context already aborted and returns before reading its cache.
      const noteFile1 = createFile('a.md');
      const noteFile2 = createFile('b.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockConfirm.mockResolvedValue(true);
      mockIsCanvasFile.mockReturnValue(false);
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      getProperAttachmentPath.mockResolvedValue('attachments/img.png');
      settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
      mockLoop.mockImplementation(async (options) => {
        const typed = castTo<LoopOptionsLike>(options);
        await typed.processItem(noteFile1);
        await typed.processItem(noteFile2);
      });
      await runOperation([noteFile1, noteFile2]);
      // GetCacheSafe runs only for the first note; the second returns early on the aborted context.
      expect(mockGetCacheSafe).toHaveBeenCalledTimes(1);
    });

    it('should return when the shared context becomes aborted during the cache read', async () => {
      // The second note is awaiting its cache read when the first note aborts the shared context,
      // So it returns right after the cache read without requesting any backlinks.
      const noteFile1 = createFile('a.md');
      const noteFile2 = createFile('b.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockConfirm.mockResolvedValue(true);
      mockIsCanvasFile.mockReturnValue(false);
      mockGetLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      getProperAttachmentPath.mockResolvedValue('attachments/img.png');
      settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;

      let resolveNote2Cache: (() => void) | undefined;
      const note2CacheGate = new Promise<void>((resolve) => {
        resolveNote2Cache = resolve;
      });
      mockGetCacheSafe.mockImplementation(async (_app, fileOrPath) => {
        if (fileOrPath === noteFile2) {
          await note2CacheGate;
        }
        return strictProxy<CachedMetadataEx>({});
      });

      mockLoop.mockImplementation(async (options) => {
        const typed = castTo<LoopOptionsLike>(options);
        const note2Promise = typed.processItem(noteFile2);
        await typed.processItem(noteFile1);
        // The first note has now aborted the shared context; release the second note's cache read.
        resolveNote2Cache?.();
        await note2Promise;
      });
      await runOperation([noteFile1, noteFile2]);
      // Only the first note reaches the backlinks request; the second returns after its cache read.
      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledTimes(1);
    });

    it('should build progress bar and notice messages', async () => {
      const noteFile = createFile('a.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockConfirm.mockResolvedValue(true);
      let noticeMessage: string | undefined;
      mockLoop.mockImplementation(async (options) => {
        noticeMessage = castTo<LoopOptionsLike>(options).buildNoticeMessage({ item: noteFile, iterationString: '1/1' });
        await noopAsync();
      });
      await runOperation([noteFile]);
      expect(noticeMessage).toContain('a.md');
    });
  });
});
