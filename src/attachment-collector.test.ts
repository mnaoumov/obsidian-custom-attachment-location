import type { CustomArrayDict } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  CachedMetadata,
  Reference,
  TAbstractFile,
  TFile,
  TFolder
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';
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
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';

import { AttachmentCollector } from './attachment-collector.ts';
import { getCanvasLinks } from './canvas-links.ts';
import { translationsMap } from './i18n/locales/translations-map.ts';
import { selectMode } from './modals/collect-attachment-used-by-multiple-notes-modal.ts';
import { CollectAttachmentUsedByMultipleNotesMode } from './plugin-settings.ts';

interface LoopOptionsLike {
  buildNoticeMessage(item: TFile, iterationStr: string): string;
  items: TFile[];
  processItem(item: TFile): Promise<void>;
}

interface QueueParamsLike {
  operationFn(abortSignal: AbortSignal): Promise<void>;
  operationName: string;
}

interface SettingsLike {
  collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode;
  getTimeoutInMilliseconds(): number;
  isExcludedFromAttachmentCollecting(path: string): boolean;
  isPathIgnored(path: string): boolean;
}

vi.mock('obsidian-dev-utils/abort-controller', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/abort-controller')>(),
  abortSignalAny: vi.fn()
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
  getAllLinks: vi.fn(),
  getBacklinksForFileSafe: vi.fn(),
  getCacheSafe: vi.fn()
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
  copySafe: vi.fn(),
  renameSafe: vi.fn()
}));

vi.mock('./canvas-links.ts', () => ({
  getCanvasLinks: vi.fn()
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
const mockGetAllLinks = vi.mocked(getAllLinks);
const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);
const mockGetCacheSafe = vi.mocked(getCacheSafe);
const mockConfirm = vi.mocked(confirm);
const mockAddToQueue = vi.mocked(addToQueue);
const mockCopySafe = vi.mocked(copySafe);
const mockRenameSafe = vi.mocked(renameSafe);
const mockGetCanvasLinks = vi.mocked(getCanvasLinks);
const mockSelectMode = vi.mocked(selectMode);

const PLUGIN_NAME = 'Custom Attachment Location';

function createBacklinks(keys: string[]): CustomArrayDict<Reference> {
  return strictProxy<CustomArrayDict<Reference>>({
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

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('AttachmentCollector', () => {
  let abortSignalComponent: AbortSignalComponent;
  let app: App;
  let attachmentPathManager: AttachmentPathManager;
  let collector: AttachmentCollector;
  let consoleDebug: Mock<(message: string, ...args: unknown[]) => void>;
  let consoleDebugComponent: ConsoleDebugComponent;
  let errorSpy: MockInstance<typeof console.error>;
  let getProperAttachmentPath: Mock<AttachmentPathManager['getProperAttachmentPath']>;
  let getRoot: Mock<() => TFolder>;
  let pluginSettingsComponent: PluginSettingsComponent;
  let readJson: Mock<(path: string) => Promise<null | object>>;
  let settings: SettingsLike;
  let warnSpy: MockInstance<typeof console.warn>;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = {
      collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode.Move,
      getTimeoutInMilliseconds: vi.fn<() => number>().mockReturnValue(1000),
      isExcludedFromAttachmentCollecting: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      isPathIgnored: vi.fn<(path: string) => boolean>().mockReturnValue(false)
    };
    getRoot = vi.fn<() => TFolder>().mockReturnValue(strictProxy<TFolder>({ path: '/' }));
    readJson = vi.fn<(path: string) => Promise<null | object>>();
    app = strictProxy<App>({
      vault: strictProxy<App['vault']>({
        getRoot: () => getRoot(),
        readJson: (path: string) => readJson(path)
      })
    });
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      isNoteEx: vi.fn<PluginSettingsComponent['isNoteEx']>().mockReturnValue(false),
      settings: castTo<PluginSettings>(settings)
    });
    getProperAttachmentPath = vi.fn<AttachmentPathManager['getProperAttachmentPath']>().mockResolvedValue('attachments/img.png');
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getProperAttachmentPath: (params) => getProperAttachmentPath(params)
    });
    abortSignalComponent = strictProxy<AbortSignalComponent>({
      abortSignal: new AbortController().signal
    });
    consoleDebug = vi.fn<(message: string, ...args: unknown[]) => void>();
    consoleDebugComponent = strictProxy<ConsoleDebugComponent>({
      consoleDebug: (message: string, ...args: unknown[]) => {
        consoleDebug(message, ...args);
      }
    });
    collector = new AttachmentCollector({
      abortSignalComponent,
      app,
      attachmentPathManager,
      consoleDebugComponent,
      pluginName: PLUGIN_NAME,
      pluginSettingsComponent
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
      await params.operationFn(new AbortController().signal);
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

  describe('collectAttachments (via queue operationFn)', () => {
    let note: TFile;

    async function runSingleFile(noteFile: TFile): Promise<void> {
      mockIsFile.mockReturnValue(true);
      mockAbortSignalAny.mockReturnValue(new AbortController().signal);
      mockLoop.mockImplementation(async (options) => {
        await castTo<LoopOptionsLike>(options).processItem(noteFile);
      });
      collector.collectAttachmentsInAbstractFiles([noteFile]);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      await params.operationFn(new AbortController().signal);
    }

    beforeEach(() => {
      note = createFile('note.md');
      mockIsCanvasFile.mockReturnValue(false);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadata>({}));
      mockGetAllLinks.mockReturnValue([]);
      getProperAttachmentPath.mockResolvedValue('attachments/img.png');
    });

    it('should return when there is no cache', async () => {
      mockGetCacheSafe.mockResolvedValue(null);
      await runSingleFile(note);
      expect(mockGetAllLinks).not.toHaveBeenCalled();
    });

    it('should read links from a canvas file', async () => {
      mockIsCanvasFile.mockReturnValue(true);
      mockGetCanvasLinks.mockResolvedValue([]);
      await runSingleFile(note);
      expect(mockGetCanvasLinks).toHaveBeenCalledWith(app, note);
      expect(mockGetAllLinks).not.toHaveBeenCalled();
    });

    it('should skip when the attachment cannot be prepared (no link file)', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(null);
      await runSingleFile(note);
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
    });

    it('should skip when the link file is a note', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('other.md'));
      vi.mocked(pluginSettingsComponent.isNoteEx).mockReturnValue(true);
      await runSingleFile(note);
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
    });

    it('should skip when the attachment was already seen', async () => {
      mockGetAllLinks.mockReturnValue([createReference(), createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      mockRenameSafe.mockResolvedValue('attachments/img.png');
      await runSingleFile(note);
      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledTimes(1);
    });

    it('should skip when the attachment could not be resolved (deleted)', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png', true));
      await runSingleFile(note);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('could not be resolved'));
    });

    it('should skip when the attachment is excluded from collecting', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      vi.mocked(settings.isExcludedFromAttachmentCollecting).mockReturnValue(true);
      await runSingleFile(note);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('excluded from attachment collecting'));
    });

    it('should move a single-referenced attachment', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      mockRenameSafe.mockResolvedValue('attachments/img.png');
      await runSingleFile(note);
      expect(mockRenameSafe).toHaveBeenCalledWith(app, 'img.png', 'attachments/img.png');
    });

    it('should not rename when the new attachment path is null (single-ref)', async () => {
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      getProperAttachmentPath.mockResolvedValue(null);
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md']));
      await runSingleFile(note);
      expect(mockRenameSafe).not.toHaveBeenCalled();
    });

    describe('multiple backlinks', () => {
      beforeEach(() => {
        mockGetAllLinks.mockReturnValue([createReference()]);
        mockExtractLinkFile.mockReturnValue(createFile('img.png'));
        mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      });

      it('should cancel and abort in Cancel mode', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
        await runSingleFile(note);
        expect(errorSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
        expect(mockSelectMode).toHaveBeenCalledWith(app, 'img.png', ['note.md', 'other.md'], true);
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
        mockEditLinks.mockImplementation(async (_app, _note, linkConverter) => {
          matchingResult = await linkConverter(createReference({ link: 'img.png' }));
          nonMatchingResult = await linkConverter(createReference({ link: 'other.png' }));
        });
        mockExtractLinkFile.mockImplementation((_app, ref) => castTo<Reference>(ref).link === 'other.png' ? createFile('other.png') : createFile('img.png'));
        mockUpdateLink.mockReturnValue('![](attachments/img.png)');
        await runSingleFile(note);
        expect(mockCopySafe).toHaveBeenCalledWith(app, 'img.png', 'attachments/img.png');
        expect(matchingResult).toBe('![](attachments/img.png)');
        expect(nonMatchingResult).toBeUndefined();
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
        expect(mockRenameSafe).toHaveBeenCalledWith(app, 'img.png', 'attachments/img.png');
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
        expect(mockSelectMode).toHaveBeenCalledWith(app, 'img.png', ['note.md', 'other.md']);
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
        mockGetAllLinks.mockReturnValue([createReference({ link: 'a.png' }), createReference({ link: 'b.png' })]);
        mockExtractLinkFile.mockImplementation((_app, ref) => createFile(castTo<Reference>(ref).link));
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

      it('should use the ctx mode when present', async () => {
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Prompt;
        mockSelectMode.mockResolvedValue({
          mode: CollectAttachmentUsedByMultipleNotesMode.Skip,
          shouldUseSameActionForOtherProblematicAttachments: true
        });
        mockGetAllLinks.mockReturnValue([createReference({ link: 'a.png' }), createReference({ link: 'b.png' })]);
        mockExtractLinkFile.mockImplementation((_app, ref) => createFile(castTo<Reference>(ref).link));
        await runSingleFile(note);
        // Prompt chosen once, then ctx mode (Skip) reused for the second link.
        expect(mockSelectMode).toHaveBeenCalledTimes(1);
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('referenced by multiple notes'));
      });

      it('should return early on a subsequent link iteration once ctx becomes aborted', async () => {
        // Two links: the first triggers Cancel (aborting ctx), so the second link
        // Iteration returns early before requesting its backlinks.
        settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
        mockGetAllLinks.mockReturnValue([createReference({ link: 'a.png' }), createReference({ link: 'b.png' })]);
        mockExtractLinkFile.mockImplementation((_app, ref) => createFile(castTo<Reference>(ref).link));
        await runSingleFile(note);
        expect(mockGetBacklinksForFileSafe).toHaveBeenCalledTimes(1);
      });
    });

    it('should show the notice while running and hide it in the finally block', async () => {
      const hideSpy = vi.spyOn(Notice.prototype, 'hide');
      mockGetAllLinks.mockReturnValue([]);
      await runSingleFile(note);
      expect(hideSpy).toHaveBeenCalled();
      hideSpy.mockRestore();
    });
  });

  describe('collectAttachmentsInAbstractFilesImpl (via queue operationFn)', () => {
    async function runOperation(abstractFiles: TAbstractFile[]): Promise<void> {
      collector.collectAttachmentsInAbstractFiles(abstractFiles);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      await params.operationFn(new AbortController().signal);
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
      await expect(params.operationFn(controller.signal)).rejects.toThrow();
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
      expect(consoleDebug).toHaveBeenCalledWith(expect.stringContaining('Collect attachments in files'));
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
      mockGetAllLinks.mockReturnValue([createReference()]);
      mockExtractLinkFile.mockReturnValue(createFile('img.png'));
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadata>({}));
      getProperAttachmentPath.mockResolvedValue('attachments/img.png');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'other.md']));
      settings.collectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Cancel;
      mockLoop.mockImplementation(async (options) => {
        await castTo<LoopOptionsLike>(options).processItem(noteFile);
      });
      await runOperation([noteFile]);
      expect(errorSpy).toHaveBeenCalled();
    });

    it('should return early for a later note once the shared ctx is aborted', async () => {
      // The first note triggers Cancel (aborting the shared ctx); the second note then
      // Enters collectAttachments with ctx already aborted and returns before reading its cache.
      const noteFile1 = createFile('a.md');
      const noteFile2 = createFile('b.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockConfirm.mockResolvedValue(true);
      mockIsCanvasFile.mockReturnValue(false);
      mockGetAllLinks.mockReturnValue([createReference()]);
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
      // GetCacheSafe runs only for the first note; the second returns early on the aborted ctx.
      expect(mockGetCacheSafe).toHaveBeenCalledTimes(1);
    });

    it('should return when the shared ctx becomes aborted during the cache read', async () => {
      // The second note is awaiting its cache read when the first note aborts the shared ctx,
      // So it returns right after the cache read without requesting any backlinks.
      const noteFile1 = createFile('a.md');
      const noteFile2 = createFile('b.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockConfirm.mockResolvedValue(true);
      mockIsCanvasFile.mockReturnValue(false);
      mockGetAllLinks.mockReturnValue([createReference()]);
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
        return strictProxy<CachedMetadata>({});
      });

      mockLoop.mockImplementation(async (options) => {
        const typed = castTo<LoopOptionsLike>(options);
        const note2Promise = typed.processItem(noteFile2);
        await typed.processItem(noteFile1);
        // The first note has now aborted the shared ctx; release the second note's cache read.
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
        noticeMessage = castTo<LoopOptionsLike>(options).buildNoticeMessage(noteFile, '1/1');
        await noopAsync();
      });
      await runOperation([noteFile]);
      expect(noticeMessage).toContain('a.md');
    });
  });
});
