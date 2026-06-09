import type {
  App,
  Reference,
  TAbstractFile,
  TFile,
  TFolder
} from 'obsidian';
import type { PathOrAbstractFile } from 'obsidian-dev-utils/obsidian/file-system';
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
import {
  getPath,
  isCanvasFile,
  isFile,
  isFolder,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import {
  editLinks,
  extractLinkFile,
  updateLink
} from 'obsidian-dev-utils/obsidian/link';
import { loop } from 'obsidian-dev-utils/obsidian/loop';
import {
  getAllLinks,
  getBacklinksForFileSafe,
  getCacheSafe
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { addToQueue } from 'obsidian-dev-utils/obsidian/queue';
import {
  copySafe,
  renameSafe
} from 'obsidian-dev-utils/obsidian/vault';
import { makeFileName } from 'obsidian-dev-utils/path';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { Plugin } from './plugin.ts';

import {
  getAttachmentFolderFullPathForPath,
  getGeneratedAttachmentFileBaseName
} from './attachment-path.ts';
import { selectMode } from './modals/collect-attachment-used-by-multiple-notes-modal.ts';
import { CollectAttachmentUsedByMultipleNotesMode } from './plugin-settings.ts';

vi.mock('obsidian', async (importOriginal) => {
  const actual = await importOriginal<typeof import('obsidian')>();
  const noticeHide = vi.fn();
  class MockNotice {
    public static instances: MockNotice[] = [];
    public hide = noticeHide;

    public constructor(_message: unknown, _timeout?: number) {
      MockNotice.instances.push(this);
    }
  }
  return {
    ...actual,
    Notice: MockNotice
  };
});

vi.mock('obsidian-dev-utils/abort-controller', () => ({
  abortSignalAny: vi.fn()
}));

vi.mock('obsidian-dev-utils/html-element', () => ({
  appendCodeBlock: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/file-system', () => ({
  getPath: vi.fn(),
  isCanvasFile: vi.fn(),
  isFile: vi.fn(),
  isFolder: vi.fn(),
  isNote: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/i18n/i18n', () => {
  const deepProxy: unknown = new Proxy(() => 'translated', {
    get: (): unknown => deepProxy
  });
  return {
    t: vi.fn((selector: (translations: unknown) => unknown) => {
      selector(deepProxy);
      return 'translated';
    })
  };
});

vi.mock('obsidian-dev-utils/obsidian/link', () => ({
  editLinks: vi.fn(),
  extractLinkFile: vi.fn(),
  updateLink: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/loop', () => ({
  loop: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/metadata-cache', () => ({
  getAllLinks: vi.fn(),
  getBacklinksForFileSafe: vi.fn(),
  getCacheSafe: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/modals/confirm', () => ({
  confirm: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/queue', () => ({
  addToQueue: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/vault', () => ({
  copySafe: vi.fn(),
  renameSafe: vi.fn()
}));

vi.mock('obsidian-dev-utils/path', async (importOriginal) => {
  const actual = await importOriginal<typeof import('obsidian-dev-utils/path')>();
  return {
    ...actual,
    makeFileName: vi.fn()
  };
});

vi.mock('./attachment-path.ts', () => ({
  getAttachmentFolderFullPathForPath: vi.fn(),
  getGeneratedAttachmentFileBaseName: vi.fn()
}));

vi.mock('./modals/collect-attachment-used-by-multiple-notes-modal.ts', () => ({
  selectMode: vi.fn()
}));

vi.mock('./substitutions.ts', () => ({
  // eslint-disable-next-line @typescript-eslint/no-extraneous-class -- Mock stands in for the real Substitutions class.
  Substitutions: class {
    // eslint-disable-next-line @typescript-eslint/no-useless-constructor -- Mock constructor matches the real signature.
    public constructor(_params: unknown) {
      // No-op.
    }
  }
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import {
  collectAttachments,
  collectAttachmentsEntireVault,
  collectAttachmentsInAbstractFiles,
  getProperAttachmentPath,
  isNoteEx
} from './attachment-collector.ts';

interface CtxLike {
  collectAttachmentUsedByMultipleNotesMode?: CollectAttachmentUsedByMultipleNotesMode;
  isAborted?: boolean;
}

interface LoopOptionsLike {
  buildNoticeMessage(item: TFile, iterationStr: string): string;
  items: TFile[];
  processItem(item: TFile): Promise<void>;
}

interface NoticeMockLike {
  hide: ReturnType<typeof vi.fn>;
}

interface NoticeStaticLike {
  instances: NoticeMockLike[];
}

interface QueueParamsLike {
  app: App;
  operationFn(abortSignal: AbortSignal): Promise<void>;
  operationName: string;
}

interface SettingsLike {
  collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode;
  getTimeoutInMilliseconds(): number;
  isExcludedFromAttachmentCollecting(path: string): boolean;
  isPathIgnored(path: string): boolean;
  shouldRenameCollectedAttachments: boolean;
  treatAsAttachmentExtensions: string[];
}

const mockAbortSignalAny = vi.mocked(abortSignalAny);
const mockGetPath = vi.mocked(getPath);
const mockIsCanvasFile = vi.mocked(isCanvasFile);
const mockIsFile = vi.mocked(isFile);
const mockIsFolder = vi.mocked(isFolder);
const mockIsNote = vi.mocked(isNote);
const mockEditLinks = vi.mocked(editLinks);
const mockExtractLinkFile = vi.mocked(extractLinkFile);
const mockUpdateLink = vi.mocked(updateLink);
const mockLoop = vi.mocked(loop);
const mockGetAllLinks = vi.mocked(getAllLinks);
const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);
const mockGetCacheSafe = vi.mocked(getCacheSafe);
const mockConfirm = vi.mocked(confirm);
const mockAddToQueue = vi.mocked(addToQueue);
const mockCopySafe = vi.mocked(copySafe);
const mockRenameSafe = vi.mocked(renameSafe);
const mockMakeFileName = vi.mocked(makeFileName);
const mockGetAttachmentFolderFullPathForPath = vi.mocked(getAttachmentFolderFullPathForPath);
const mockGetGeneratedAttachmentFileBaseName = vi.mocked(getGeneratedAttachmentFileBaseName);
const mockSelectMode = vi.mocked(selectMode);

function createBacklinks(keys: string[]): Awaited<ReturnType<typeof getBacklinksForFileSafe>> {
  return strictProxy<Awaited<ReturnType<typeof getBacklinksForFileSafe>>>({
    keys: () => keys
  });
}

function createFile(path: string, deleted = false): TFile {
  return strictProxy<TFile>({
    deleted,
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

describe('attachment-collector', () => {
  let app: App;
  let plugin: Plugin;
  let pluginSettingsComponent: PluginSettingsComponent;
  let readJson: Mock<(path: string) => Promise<null | object>>;
  let readBinary: Mock<(file: TFile) => Promise<ArrayBuffer>>;
  let getRoot: Mock<() => TFolder>;
  let getSequenceNumber: Mock<(noteFilePath: string, attachmentPath: string) => Promise<number>>;
  let settings: SettingsLike;
  let warnSpy: MockInstance<typeof console.warn>;
  let errorSpy: MockInstance<typeof console.error>;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = {
      collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode.Move,
      getTimeoutInMilliseconds: vi.fn<() => number>().mockReturnValue(1000),
      isExcludedFromAttachmentCollecting: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      isPathIgnored: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      shouldRenameCollectedAttachments: false,
      treatAsAttachmentExtensions: []
    };
    readJson = vi.fn<(path: string) => Promise<null | object>>();
    readBinary = vi.fn<(file: TFile) => Promise<ArrayBuffer>>().mockResolvedValue(new ArrayBuffer(0));
    getRoot = vi.fn<() => TFolder>().mockReturnValue(strictProxy<TFolder>({ path: '/' }));
    getSequenceNumber = vi.fn<(noteFilePath: string, attachmentPath: string) => Promise<number>>().mockResolvedValue(0);
    app = strictProxy<App>({
      vault: strictProxy<App['vault']>({
        getRoot,
        readBinary: (file: TFile) => readBinary(file),
        readJson
      })
    });
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      settings: castTo<PluginSettingsComponent['settings']>(settings)
    });
    plugin = strictProxy<Plugin>({
      app,
      getSequenceNumber: (noteFilePath: string, attachmentPath: string) => getSequenceNumber(noteFilePath, attachmentPath),
      manifest: strictProxy<Plugin['manifest']>({ name: 'Plugin' })
    });
    mockMakeFileName.mockImplementation((base: string, ext: string) => `${base}.${ext}`);
    mockGetGeneratedAttachmentFileBaseName.mockResolvedValue('renamed');
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
    errorSpy.mockRestore();
  });

  describe('isNoteEx', () => {
    it('should return false when pathOrFile is null', () => {
      expect(isNoteEx(plugin, null, pluginSettingsComponent)).toBe(false);
    });

    it('should return false when not a note', () => {
      mockIsNote.mockReturnValue(false);
      expect(isNoteEx(plugin, castTo<PathOrAbstractFile>('img.png'), pluginSettingsComponent)).toBe(false);
    });

    it('should return true when a note and not treated as attachment', () => {
      mockIsNote.mockReturnValue(true);
      mockGetPath.mockReturnValue('note.md');
      settings.treatAsAttachmentExtensions = ['.excalidraw.md'];
      expect(isNoteEx(plugin, castTo<PathOrAbstractFile>('note.md'), pluginSettingsComponent)).toBe(true);
    });

    it('should return false when path ends with a treated-as-attachment extension', () => {
      mockIsNote.mockReturnValue(true);
      mockGetPath.mockReturnValue('a.excalidraw.md');
      settings.treatAsAttachmentExtensions = ['.excalidraw.md'];
      expect(isNoteEx(plugin, castTo<PathOrAbstractFile>('a.excalidraw.md'), pluginSettingsComponent)).toBe(false);
    });
  });

  describe('getProperAttachmentPath', () => {
    it('should return null when the new path equals the current path', async () => {
      const attachmentFile = createFile('img.png');
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('');
      const result = await getProperAttachmentPath({
        actionContext: castTo<Parameters<typeof getProperAttachmentPath>[0]['actionContext']>('CollectAttachments'),
        attachmentFile,
        noteFilePath: 'note.md',
        plugin,
        pluginSettingsComponent,
        reference: createReference()
      });
      expect(result).toBeNull();
    });

    it('should return the new path when it differs', async () => {
      const attachmentFile = createFile('img.png');
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      const result = await getProperAttachmentPath({
        actionContext: castTo<Parameters<typeof getProperAttachmentPath>[0]['actionContext']>('CollectAttachments'),
        attachmentFile,
        noteFilePath: 'note.md',
        plugin,
        pluginSettingsComponent,
        reference: createReference()
      });
      expect(result).toBe('attachments/img.png');
    });

    it('should rename the collected attachment when shouldRenameCollectedAttachments is set', async () => {
      settings.shouldRenameCollectedAttachments = true;
      const attachmentFile = createFile('img.png');
      mockGetGeneratedAttachmentFileBaseName.mockResolvedValue('renamed');
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      const result = await getProperAttachmentPath({
        actionContext: castTo<Parameters<typeof getProperAttachmentPath>[0]['actionContext']>('CollectAttachments'),
        attachmentFile,
        noteFilePath: 'note.md',
        plugin,
        pluginSettingsComponent,
        reference: castTo<Reference>({
          link: 'img.png',
          original: '![[img.png]]',
          position: { end: { col: 0, line: 3, loc: 0, offset: 0 }, start: { col: 0, line: 3, loc: 0, offset: 0 } }
        })
      });
      expect(mockGetGeneratedAttachmentFileBaseName).toHaveBeenCalledOnce();
      expect(result).toBe('attachments/renamed.png');
    });

    it('should use cursor line 0 when the reference is not a reference cache', async () => {
      settings.shouldRenameCollectedAttachments = true;
      const attachmentFile = createFile('img.png');
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      const result = await getProperAttachmentPath({
        actionContext: castTo<Parameters<typeof getProperAttachmentPath>[0]['actionContext']>('CollectAttachments'),
        attachmentFile,
        noteFilePath: 'note.md',
        plugin,
        pluginSettingsComponent,
        reference: castTo<Reference>({ key: 'frontmatterKey', link: 'img.png', original: 'img.png' })
      });
      expect(result).toBe('attachments/renamed.png');
    });
  });

  describe('collectAttachmentsEntireVault', () => {
    it('should enqueue an operation for the vault root', () => {
      const abortSignalComponent = strictProxy<Parameters<typeof collectAttachmentsEntireVault>[1]>({ abortSignal: new AbortController().signal });
      const consoleDebugComponent = strictProxy<Parameters<typeof collectAttachmentsEntireVault>[3]>({ consoleDebug: vi.fn() });
      collectAttachmentsEntireVault(plugin, abortSignalComponent, pluginSettingsComponent, consoleDebugComponent);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      expect(params.app).toBe(app);
      expect(params.operationName).toBe('translated');
    });

    it('should run the operation against the vault root', async () => {
      const abortSignalComponent = strictProxy<Parameters<typeof collectAttachmentsEntireVault>[1]>({ abortSignal: new AbortController().signal });
      const consoleDebugComponent = strictProxy<Parameters<typeof collectAttachmentsEntireVault>[3]>({ consoleDebug: vi.fn() });
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockLoop.mockResolvedValue(undefined);
      mockConfirm.mockResolvedValue(true);
      mockIsFile.mockReturnValue(false);
      mockIsFolder.mockReturnValue(false);
      collectAttachmentsEntireVault(plugin, abortSignalComponent, pluginSettingsComponent, consoleDebugComponent);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      await params.operationFn(new AbortController().signal);
      expect(getRoot).toHaveBeenCalled();
      expect(mockLoop).toHaveBeenCalled();
    });
  });

  describe('collectAttachmentsInAbstractFiles', () => {
    it('should enqueue an operation for the given files', () => {
      const abortSignalComponent = strictProxy<Parameters<typeof collectAttachmentsInAbstractFiles>[2]>({ abortSignal: new AbortController().signal });
      const consoleDebugComponent = strictProxy<Parameters<typeof collectAttachmentsInAbstractFiles>[4]>({ consoleDebug: vi.fn() });
      const files = [strictProxy<TAbstractFile>({ path: 'a.md' })];
      collectAttachmentsInAbstractFiles(plugin, files, abortSignalComponent, pluginSettingsComponent, consoleDebugComponent);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      expect(params.app).toBe(app);
    });
  });

  describe('collectAttachments', () => {
    let abortSignal: AbortSignal;
    let note: TFile;

    beforeEach(() => {
      abortSignal = new AbortController().signal;
      note = createFile('note.md');
      mockIsCanvasFile.mockReturnValue(false);
      mockGetCacheSafe.mockResolvedValue(castTo<Awaited<ReturnType<typeof getCacheSafe>>>({}));
      mockGetAllLinks.mockReturnValue([]);
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
    });

    it('should throw immediately when the signal is already aborted', async () => {
      const controller = new AbortController();
      controller.abort();
      await expect(collectAttachments(plugin, note, {}, controller.signal, pluginSettingsComponent)).rejects.toThrow();
    });

    it('should return early when ctx.isAborted is true', async () => {
      await collectAttachments(plugin, note, { isAborted: true }, abortSignal, pluginSettingsComponent);
      expect(mockGetCacheSafe).not.toHaveBeenCalled();
    });

    it('should return when ctx becomes aborted after reading the cache', async () => {
      const ctx = { isAborted: false };
      mockGetCacheSafe.mockImplementation(async () => {
        ctx.isAborted = true;
        return Promise.resolve(castTo<Awaited<ReturnType<typeof getCacheSafe>>>({}));
      });
      await collectAttachments(plugin, note, ctx, abortSignal, pluginSettingsComponent);
      expect(mockGetAllLinks).not.toHaveBeenCalled();
    });

    it('should return when there is no cache', async () => {
      mockGetCacheSafe.mockResolvedValue(null);
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(mockGetAllLinks).not.toHaveBeenCalled();
    });

    it('should read links from a canvas file', async () => {
      mockIsCanvasFile.mockReturnValue(true);
      readJson.mockResolvedValue({
        nodes: [
          { file: 'canvas-img.png', type: 'file' },
          { type: 'text' }
        ]
      });
      mockExtractLinkFile.mockReturnValue(null);
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(readJson).toHaveBeenCalledWith('note.md');
      expect(mockGetAllLinks).not.toHaveBeenCalled();
    });

    it('should skip when the attachment cannot be prepared (no link file)', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(null);
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
    });

    it('should skip when the link file is a note', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('other.md'));
      mockIsNote.mockReturnValue(true);
      mockGetPath.mockReturnValue('other.md');
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
    });

    it('should skip when the attachment was already seen', async () => {
      mockGetAllLinks.mockReturnValue([createReference(), createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockIsNote.mockReturnValue(false);
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      mockRenameSafe.mockResolvedValue('attachments/img.png');
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledTimes(1);
    });

    it('should skip when the attachment could not be resolved (deleted)', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png', true));
      mockIsNote.mockReturnValue(false);
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('could not be resolved'));
    });

    it('should skip when the attachment is excluded from collecting', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockIsNote.mockReturnValue(false);
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      vi.mocked(settings.isExcludedFromAttachmentCollecting).mockReturnValue(true);
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('excluded from attachment collecting'));
    });

    it('should move a single-referenced attachment', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockIsNote.mockReturnValue(false);
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      mockRenameSafe.mockResolvedValue('attachments/img.png');
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(mockRenameSafe).toHaveBeenCalledWith(app, 'img.png', 'attachments/img.png');
    });

    it('should not rename when the new attachment path is null (single-ref)', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockIsNote.mockReturnValue(false);
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(mockRenameSafe).not.toHaveBeenCalled();
    });

    describe('multiple backlinks', () => {
      beforeEach(() => {
        mockGetAllLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile('img.png'));
        mockIsNote.mockReturnValue(false);
        mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      });

      it('should cancel and abort in Cancel mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
        mockSelectMode.mockResolvedValue({ mode: CollectAttachmentUsedByMultipleNotesMode.Cancel, shouldUseSameActionForOtherProblematicAttachments: false });
        const ctx = {};
        await collectAttachments(plugin, note, ctx, abortSignal, pluginSettingsComponent);
        expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
        expect(mockSelectMode).toHaveBeenCalledWith(app, 'img.png', ['note.md', 'other.md'], true);
        expect(castTo<CtxLike>(ctx).isAborted).toBe(true);
      });

      it('should not invoke selectMode in Cancel mode when the setting differs', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Move;
        const ctx = { collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode.Cancel };
        await collectAttachments(plugin, note, ctx, abortSignal, pluginSettingsComponent);
        expect(mockSelectMode).not.toHaveBeenCalled();
        expect(errorSpy).toHaveBeenCalled();
      });

      it('should copy and rewrite links in Copy mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        mockCopySafe.mockResolvedValue('attachments/img.png');
        let matchingResult: unknown;
        let nonMatchingResult: unknown;
        mockEditLinks.mockImplementation(async (_app, _note, linkHandler) => {
          matchingResult = linkHandler(createReference({ link: 'img.png' }));
          nonMatchingResult = linkHandler(createReference({ link: 'other.png' }));
          await noopAsync();
        });
        mockExtractLinkFile.mockImplementation((_app, ref) => {
          return castTo<Reference>(ref).link === 'other.png' ? createFile('other.png') : createFile('img.png');
        });
        mockUpdateLink.mockReturnValue('![](attachments/img.png)');
        await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
        expect(mockCopySafe).toHaveBeenCalledWith(app, 'img.png', 'attachments/img.png');
        expect(matchingResult).toBe('![](attachments/img.png)');
        expect(nonMatchingResult).toBeUndefined();
      });

      it('should skip Copy mode when the new attachment path is null', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        mockGetAttachmentFolderFullPathForPath.mockResolvedValue('');
        await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
        expect(mockCopySafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('already in the destination folder'));
      });

      it('should fall back to empty string when copying and newAttachmentPath becomes falsy', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Copy;
        mockCopySafe.mockResolvedValue('');
        let handlerResult: unknown;
        mockEditLinks.mockImplementation(async (_app, _note, linkHandler) => {
          handlerResult = linkHandler(createReference({ link: 'img.png' }));
          await noopAsync();
        });
        mockExtractLinkFile.mockReturnValue(createFile('img.png'));
        mockUpdateLink.mockReturnValue('![](img.png)');
        await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
        expect(handlerResult).toBe('![](img.png)');
        expect(mockUpdateLink).toHaveBeenCalledWith(expect.objectContaining({ newTargetPathOrFile: '' }));
      });

      it('should move in Move mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Move;
        mockRenameSafe.mockResolvedValue('attachments/img.png');
        await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
        expect(mockRenameSafe).toHaveBeenCalledWith(app, 'img.png', 'attachments/img.png');
      });

      it('should skip Move mode when the new attachment path is null', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Move;
        mockGetAttachmentFolderFullPathForPath.mockResolvedValue('');
        await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
        expect(mockRenameSafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('already in the destination folder'));
      });

      it('should skip in Skip mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;
        await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
        expect(mockRenameSafe).not.toHaveBeenCalled();
      });

      it('should prompt and apply the chosen mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Prompt;
        mockSelectMode.mockResolvedValue({ mode: CollectAttachmentUsedByMultipleNotesMode.Move, shouldUseSameActionForOtherProblematicAttachments: false });
        mockRenameSafe.mockResolvedValue('attachments/img.png');
        await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
        expect(mockSelectMode).toHaveBeenCalledWith(app, 'img.png', ['note.md', 'other.md']);
        expect(mockRenameSafe).toHaveBeenCalled();
      });

      it('should remember the chosen mode for other attachments when requested', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Prompt;
        mockSelectMode.mockResolvedValue({ mode: CollectAttachmentUsedByMultipleNotesMode.Skip, shouldUseSameActionForOtherProblematicAttachments: true });
        const ctx: CtxLike = {};
        await collectAttachments(plugin, note, ctx, abortSignal, pluginSettingsComponent);
        expect(ctx.collectAttachmentUsedByMultipleNotesMode).toBe(CollectAttachmentUsedByMultipleNotesMode.Skip);
      });

      it('should throw for an unknown mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = castTo<CollectAttachmentUsedByMultipleNotesMode>('Unknown');
        await expect(collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent)).rejects.toThrow(
          'Unknown collect attachment used by multiple notes mode'
        );
      });

      it('should use the ctx mode when present', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Move;
        const ctx = { collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode.Skip };
        await collectAttachments(plugin, note, ctx, abortSignal, pluginSettingsComponent);
        expect(mockRenameSafe).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
      });
    });

    it('should return early on a subsequent link iteration once ctx becomes aborted', async () => {
      mockGetAllLinks.mockReturnValue([createReference({ link: 'a.png' }), createReference({ link: 'b.png' })]);
      mockExtractLinkFile.mockReturnValue(createFile('a.png'));
      mockIsNote.mockReturnValue(false);
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
      const ctx = {};
      await collectAttachments(plugin, note, ctx, abortSignal, pluginSettingsComponent);
      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledTimes(1);
      expect(castTo<CtxLike>(ctx).isAborted).toBe(true);
    });

    it('should show the notice while running and hide it in the finally block', async () => {
      const noticeInstances = castTo<NoticeStaticLike>(Notice).instances;
      noticeInstances.length = 0;
      mockGetAllLinks.mockReturnValue([]);
      await collectAttachments(plugin, note, {}, abortSignal, pluginSettingsComponent);
      expect(noticeInstances.length).toBeGreaterThanOrEqual(1);
      expect(noticeInstances[0]?.hide).toHaveBeenCalled();
    });
  });

  describe('collectAttachmentsInAbstractFilesImpl (via queue operationFn)', () => {
    let abortSignalComponent: Parameters<typeof collectAttachmentsInAbstractFiles>[2];
    let consoleDebugComponent: Parameters<typeof collectAttachmentsInAbstractFiles>[4];

    async function runOperation(abstractFiles: TAbstractFile[]): Promise<void> {
      collectAttachmentsInAbstractFiles(plugin, abstractFiles, abortSignalComponent, pluginSettingsComponent, consoleDebugComponent);
      const params = mockAddToQueue.mock.calls[0]?.[0];
      const operationFn = castTo<QueueParamsLike>(params).operationFn;
      await operationFn(new AbortController().signal);
    }

    beforeEach(() => {
      abortSignalComponent = strictProxy<Parameters<typeof collectAttachmentsInAbstractFiles>[2]>({ abortSignal: new AbortController().signal });
      consoleDebugComponent = strictProxy<Parameters<typeof collectAttachmentsInAbstractFiles>[4]>({ consoleDebug: vi.fn() });
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockLoop.mockResolvedValue(undefined);
    });

    it('should throw when the signal is already aborted', async () => {
      collectAttachmentsInAbstractFiles(plugin, [], abortSignalComponent, pluginSettingsComponent, consoleDebugComponent);
      const params = mockAddToQueue.mock.calls[0]?.[0];
      const operationFn = castTo<QueueParamsLike>(params).operationFn;
      const controller = new AbortController();
      controller.abort();
      await expect(operationFn(controller.signal)).rejects.toThrow();
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
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, cb) => {
        cb(childNote);
      });
      try {
        await runOperation([noteFile, folder]);
      } finally {
        recurseSpy.mockRestore();
      }
      const loopOptions = castTo<LoopOptionsLike>(mockLoop.mock.calls[0]?.[0]);
      expect(loopOptions.items).toEqual([noteFile, childNote]);
    });

    it('should skip a non-note child during folder recursion', async () => {
      const folder = strictProxy<TAbstractFile>({ path: 'folder' });
      const childNonNote = createFile('folder/img.png');
      mockIsFile.mockReturnValue(false);
      mockIsFolder.mockImplementation((f) => f === folder);
      mockIsNote.mockReturnValue(false);
      mockConfirm.mockResolvedValue(true);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, cb) => {
        cb(childNonNote);
      });
      try {
        await runOperation([folder]);
      } finally {
        recurseSpy.mockRestore();
      }
      const loopOptions = castTo<LoopOptionsLike>(mockLoop.mock.calls[0]?.[0]);
      expect(loopOptions.items).toEqual([]);
    });

    it('should process each note via loop processItem', async () => {
      const noteFile = createFile('a.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockGetCacheSafe.mockResolvedValue(null);
      mockLoop.mockImplementation(async (options) => {
        await castTo<LoopOptionsLike>(options).processItem(noteFile);
      });
      await runOperation([noteFile]);
      expect(mockGetCacheSafe).toHaveBeenCalledWith(app, noteFile);
    });

    it('should skip an ignored note inside loop processItem', async () => {
      const noteFile = createFile('a.md');
      const otherFile = createFile('b.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockConfirm.mockResolvedValue(true);
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
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
      mockIsNote.mockReturnValue(false);
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetCacheSafe.mockResolvedValue(castTo<Awaited<ReturnType<typeof getCacheSafe>>>({}));
      mockGetAttachmentFolderFullPathForPath.mockResolvedValue('attachments');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
      mockLoop.mockImplementation(async (options) => {
        await castTo<LoopOptionsLike>(options).processItem(noteFile);
      });
      await runOperation([noteFile]);
      expect(errorSpy).toHaveBeenCalled();
    });

    it('should build progress bar and notice messages', async () => {
      const noteFile = createFile('a.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockLoop.mockImplementation(async (options) => {
        const typed = castTo<LoopOptionsLike>(options);
        expect(typed.buildNoticeMessage(noteFile, '1/1')).toBe('translated');
        await noopAsync();
      });
      await runOperation([noteFile]);
      expect(mockLoop).toHaveBeenCalled();
    });
  });
});
