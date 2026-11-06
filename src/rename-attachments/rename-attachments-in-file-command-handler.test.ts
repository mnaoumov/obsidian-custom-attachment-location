import type { AbortSignalComponent } from '@mnaoumov/obsidian-lib/components/abort-signal-component';
import type { CachedMetadataEx } from '@mnaoumov/obsidian-lib/metadata-cache';
import type { CustomArrayDict } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  Reference,
  TAbstractFile,
  TFile
} from 'obsidian';

import { findAttachmentUnitFolderPath } from '@mnaoumov/obsidian-lib/attachment-unit-folder';
import { BulkOperationCommitComponent } from '@mnaoumov/obsidian-lib/components/bulk-operation-commit-component';
import { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import {
  isFile,
  isMarkdownFile
} from '@mnaoumov/obsidian-lib/file-system';
import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { extractReferenceFile } from '@mnaoumov/obsidian-lib/link';
import { loop } from '@mnaoumov/obsidian-lib/loop';
import {
  getBacklinksForFileSafe,
  getCacheSafe,
  getReferences
} from '@mnaoumov/obsidian-lib/metadata-cache';
import { addToQueueAndWait } from '@mnaoumov/obsidian-lib/queue';
import { renameSafe } from '@mnaoumov/obsidian-lib/vault';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { AttachmentPathManager } from '../attachment-location/attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { PluginSettings } from '../settings/plugin-settings.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { RenameAttachmentsInFileCommandHandler } from './rename-attachments-in-file-command-handler.ts';

interface LoopBuildNoticeMessageParamsLike {
  readonly item: LoopItemLike;
  readonly iterationString: string;
}

interface LoopItemLike {
  readonly attachmentFile: TFile;
}

interface LoopParamsLike {
  readonly buildNoticeMessage: (params: LoopBuildNoticeMessageParamsLike) => string;
  readonly items: readonly unknown[];
  readonly processItem: (item: unknown) => Promise<void>;
}

interface QueueParamsLike {
  readonly operationFunction: (abortSignal: AbortSignal) => Promise<void>;
}

interface TestableHandler {
  readonly canExecuteAbstractFile: (abstractFile: TAbstractFile) => boolean;
  readonly executeAbstractFile: (abstractFile: TAbstractFile) => Promise<void>;
  readonly fileMenuItemName: string;
  readonly icon: string;
  readonly id: string;
  readonly name: string;
  readonly shouldAddToAbstractFileMenu: () => boolean;
}

vi.mock('@mnaoumov/obsidian-lib/attachment-unit-folder', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/attachment-unit-folder')>(),
  findAttachmentUnitFolderPath: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/file-system', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/file-system')>(),
  isFile: vi.fn(),
  isMarkdownFile: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/link', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/link')>(),
  extractReferenceFile: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/loop', () => ({
  loop: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/metadata-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/metadata-cache')>(),
  getBacklinksForFileSafe: vi.fn(),
  getCacheSafe: vi.fn(),
  getReferences: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/queue', () => ({
  addToQueueAndWait: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/vault', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/vault')>(),
  renameSafe: vi.fn()
}));

const mockAddToQueueAndWait = vi.mocked(addToQueueAndWait);
const mockExtractReferenceFile = vi.mocked(extractReferenceFile);
const mockFindAttachmentUnitFolderPath = vi.mocked(findAttachmentUnitFolderPath);
const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);
const mockGetCacheSafe = vi.mocked(getCacheSafe);
const mockGetReferences = vi.mocked(getReferences);
const isFileMock = vi.mocked(isFile);
const isMarkdownFileMock = vi.mocked(isMarkdownFile);
const mockLoop = vi.mocked(loop);
const mockRenameSafe = vi.mocked(renameSafe);

const mockGetRenamedAttachmentPath = vi.fn<AttachmentPathManager['getRenamedAttachmentPath']>();
const mockGetSequenceNumberMap = vi.fn<AttachmentPathManager['getSequenceNumberMap']>();
const isExcludedFromMultipleNotesCheckMock = vi.fn<PluginSettings['isExcludedFromMultipleNotesCheck']>();
const isNoteExMock = vi.fn<PluginSettingsComponent['isNoteEx']>();
const isPathIgnoredMock = vi.fn<HandedOverSettingsComponent['isPathIgnored']>();
const mockShowNotice = vi.fn();

function createBacklinks(notePaths: readonly string[]): CustomArrayDict<Reference> {
  return strictProxy<CustomArrayDict<Reference>>({
    keys: (): string[] => [...notePaths]
  });
}

function createFile(path: string): TFile {
  const name = path.split('/').at(-1) ?? path;
  return strictProxy<TFile>({ name, path });
}

function createReference(original: string, line?: number): Reference {
  return castTo<Reference>(line === undefined ? { link: original, original } : { link: original, original, position: { end: { col: 0, line, offset: 0 }, start: { col: 0, line, offset: 0 } } });
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('RenameAttachmentsInFileCommandHandler', () => {
  let handler: RenameAttachmentsInFileCommandHandler;
  let note: TFile;
  let vaultFiles: TFile[];
  let referencedFiles: Map<string, null | TFile>;
  let references: Reference[];
  let backlinksByPath: Map<string, string[]>;
  let sidecarExtensions: string[];

  beforeEach(() => {
    vi.clearAllMocks();
    note = createFile('notes/note.md');
    vaultFiles = [note];
    referencedFiles = new Map();
    references = [];
    mockGetReferences.mockImplementation(() => references);
    backlinksByPath = new Map();
    sidecarExtensions = ['p7s'];

    isFileMock.mockReturnValue(true);
    isMarkdownFileMock.mockReturnValue(true);
    isPathIgnoredMock.mockReturnValue(false);
    isNoteExMock.mockImplementation((pathOrFile) => castTo<TFile>(pathOrFile).path.endsWith('.md'));
    isExcludedFromMultipleNotesCheckMock.mockReturnValue(false);
    mockFindAttachmentUnitFolderPath.mockReturnValue(null);
    mockGetCacheSafe.mockResolvedValue(castTo<CachedMetadataEx>({}));
    mockGetSequenceNumberMap.mockResolvedValue(new Map());
    mockExtractReferenceFile.mockImplementation(({ reference }) => referencedFiles.get(reference.link) ?? null);
    mockGetBacklinksForFileSafe.mockImplementation(({ pathOrFile }) => Promise.resolve(createBacklinks(backlinksByPath.get(castTo<TFile>(pathOrFile).path) ?? [note.path])));
    mockAddToQueueAndWait.mockImplementation(async (params) => {
      await castTo<QueueParamsLike>(params).operationFunction(new AbortController().signal);
    });
    mockLoop.mockImplementation(async (params) => {
      const loopParams = castTo<LoopParamsLike>(params);
      for (const item of loopParams.items) {
        await loopParams.processItem(item);
      }
    });
    mockRenameSafe.mockImplementation(({ newPath }) => Promise.resolve(newPath));

    const app = strictProxy<App>({
      vault: strictProxy<App['vault']>({
        getFiles: () => vaultFiles
      })
    });
    const pluginNoticeComponent = strictProxy<PluginNoticeComponent>({ showNotice: mockShowNotice });

    handler = new RenameAttachmentsInFileCommandHandler({
      abortSignalComponent: strictProxy<AbortSignalComponent>({ abortSignal: new AbortController().signal }),
      app,
      attachmentPathManager: strictProxy<AttachmentPathManager>({
        getRenamedAttachmentPath: mockGetRenamedAttachmentPath,
        getSequenceNumberMap: mockGetSequenceNumberMap
      }),
      // The real component with its setting off, which runs the operation as it is.
      bulkOperationCommitComponent: new BulkOperationCommitComponent({
        app,
        isEnabled: (): boolean => false,
        pluginId: 'test-plugin',
        pluginNoticeComponent: new PluginNoticeComponent({ app, pluginName: 'My Plugin' })
      }),
      handedOverSettingsComponent: strictProxy<HandedOverSettingsComponent>({ isPathIgnored: isPathIgnoredMock }),
      pluginNoticeComponent,
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
        isNoteEx: isNoteExMock,
        settings: strictProxy<PluginSettings>({
          getTimeoutInMilliseconds: () => 5000,
          isExcludedFromMultipleNotesCheck: isExcludedFromMultipleNotesCheckMock,
          sidecarExtensions
        })
      })
    });
  });

  function linkAttachment(path: string, line?: number): TFile {
    const file = createFile(path);
    vaultFiles.push(file);
    referencedFiles.set(path, file);
    references.push(createReference(path, line));
    return file;
  }

  it('should construct with the command metadata', () => {
    const testable = castTo<TestableHandler>(handler);
    expect(testable.id).toBe('rename-attachments-in-file');
    expect(testable.icon).toBe('text-cursor-input');
    expect(testable.name).toBe('Rename attachments in current note');
    expect(testable.fileMenuItemName).toBe('Rename attachments in file');
    expect(testable.shouldAddToAbstractFileMenu()).toBe(true);
  });

  describe('canExecuteAbstractFile', () => {
    it('should accept a Markdown note', () => {
      expect(castTo<TestableHandler>(handler).canExecuteAbstractFile(note)).toBe(true);
    });

    it('should reject a file that is not Markdown, such as a canvas', () => {
      isMarkdownFileMock.mockReturnValue(false);
      expect(castTo<TestableHandler>(handler).canExecuteAbstractFile(createFile('board.canvas'))).toBe(false);
    });

    it('should reject a folder', () => {
      isFileMock.mockReturnValue(false);
      expect(castTo<TestableHandler>(handler).canExecuteAbstractFile(createFile('folder'))).toBe(false);
    });
  });

  describe('executeAbstractFile', () => {
    it('should do nothing for a folder', async () => {
      isFileMock.mockReturnValue(false);
      await castTo<TestableHandler>(handler).executeAbstractFile(createFile('folder'));
      expect(mockAddToQueueAndWait).not.toHaveBeenCalled();
    });

    it('should refuse an ignored note with a notice', async () => {
      isPathIgnoredMock.mockReturnValue(true);
      const warn = vi.spyOn(console, 'warn').mockImplementation(vi.fn());
      await castTo<TestableHandler>(handler).executeAbstractFile(note);
      expect(mockShowNotice).toHaveBeenCalledOnce();
      expect(mockAddToQueueAndWait).not.toHaveBeenCalled();
      expect(warn).toHaveBeenCalledWith('Cannot rename attachments in the note as note path is ignored: notes/note.md.');
    });

    it('should rename each attachment in place and report the count', async () => {
      const image = linkAttachment('notes/assets/pasted.png', 4);
      // A second link to the same file is examined once, at its first link's line.
      references.push(createReference(image.path, 9));
      const pdf = linkAttachment('notes/doc.pdf');
      mockGetSequenceNumberMap.mockResolvedValue(new Map([[image.path, 1], [pdf.path, 2]]));
      mockGetRenamedAttachmentPath.mockImplementation(({ attachmentFile }) => Promise.resolve(attachmentFile === image ? 'notes/assets/file-1.png' : null));

      await castTo<TestableHandler>(handler).executeAbstractFile(note);

      expect(mockGetRenamedAttachmentPath).toHaveBeenCalledTimes(2);
      expect(mockGetRenamedAttachmentPath).toHaveBeenCalledWith({ attachmentFile: image, cursorLine: 4, noteFilePath: note.path, sequenceNumber: 1 });
      expect(mockGetRenamedAttachmentPath).toHaveBeenCalledWith({ attachmentFile: pdf, cursorLine: 0, noteFilePath: note.path, sequenceNumber: 2 });
      expect(mockRenameSafe).toHaveBeenCalledOnce();
      expect(mockRenameSafe).toHaveBeenCalledWith(expect.objectContaining({ newPath: 'notes/assets/file-1.png', oldPathOrAbstractFile: image }));
      expect(mockShowNotice).toHaveBeenCalledWith('Renamed 1 attachment(s) of \'notes/note.md\'.');
    });

    it('should build a progress message naming the attachment', async () => {
      linkAttachment('notes/a.png');
      mockGetRenamedAttachmentPath.mockResolvedValue(null);
      await castTo<TestableHandler>(handler).executeAbstractFile(note);
      const loopParams = castTo<LoopParamsLike>(mockLoop.mock.calls[0]?.[0]);
      expect(loopParams.buildNoticeMessage({ item: { attachmentFile: createFile('notes/a.png') }, iterationString: '# 1 / 1' }))
        .toBe('Renaming attachment # 1 / 1 - \'notes/a.png\'.');
    });

    it('should use sequence number 0 for an attachment the numbering does not know', async () => {
      const image = linkAttachment('notes/a.png');
      mockGetRenamedAttachmentPath.mockResolvedValue(null);
      await castTo<TestableHandler>(handler).executeAbstractFile(note);
      expect(mockGetRenamedAttachmentPath).toHaveBeenCalledWith(expect.objectContaining({ attachmentFile: image, sequenceNumber: 0 }));
    });

    it('should skip unresolved links, the note itself and linked notes, without counting them', async () => {
      references.push(createReference('missing.png'));
      referencedFiles.set('self', note);
      references.push(createReference('self'));
      const other = createFile('other.md');
      referencedFiles.set(other.path, other);
      references.push(createReference(other.path));

      await castTo<TestableHandler>(handler).executeAbstractFile(note);

      expect(mockGetRenamedAttachmentPath).not.toHaveBeenCalled();
      expect(mockShowNotice).toHaveBeenCalledWith('Renamed 0 attachment(s) of \'notes/note.md\'.');
    });

    it('should do nothing when the note has no cache', async () => {
      mockGetCacheSafe.mockResolvedValue(null);
      await castTo<TestableHandler>(handler).executeAbstractFile(note);
      expect(mockGetReferences).not.toHaveBeenCalled();
      expect(mockShowNotice).toHaveBeenCalledWith('Renamed 0 attachment(s) of \'notes/note.md\'.');
    });

    it('should leave ignored, unit-folder, sidecar and shared attachments alone, and count them', async () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(vi.fn());
      const ignored = linkAttachment('private/ignored.png');
      isPathIgnoredMock.mockImplementation((path) => path === ignored.path);
      const inUnit = linkAttachment('notes/page_files/image.png');
      mockFindAttachmentUnitFolderPath.mockImplementation(({ attachmentPath }) => attachmentPath === inUnit.path ? 'notes/page_files' : null);
      vaultFiles.push(createFile('notes/doc.html'));
      linkAttachment('notes/doc.html.p7s');
      const shared = linkAttachment('notes/shared.png');
      backlinksByPath.set(shared.path, [note.path, 'other.md']);
      const sharedWithExcluded = linkAttachment('notes/shared-with-index.png');
      backlinksByPath.set(sharedWithExcluded.path, [note.path, 'Index.md']);
      isExcludedFromMultipleNotesCheckMock.mockImplementation((path) => path === 'Index.md');
      mockGetRenamedAttachmentPath.mockResolvedValue('notes/renamed.png');

      await castTo<TestableHandler>(handler).executeAbstractFile(note);

      expect(mockGetRenamedAttachmentPath).toHaveBeenCalledOnce();
      expect(mockGetRenamedAttachmentPath).toHaveBeenCalledWith(expect.objectContaining({ attachmentFile: sharedWithExcluded }));
      expect(mockShowNotice).toHaveBeenCalledWith(
        'Renamed 1 attachment(s) of \'notes/note.md\'. Left 4 alone: shared with other notes, inside an attachment unit folder, a sidecar, or ignored. The console names each one.'
      );
      expect(warn).toHaveBeenCalledWith('Skipping renaming attachment private/ignored.png as its path is ignored.');
      expect(warn).toHaveBeenCalledWith('Skipping renaming attachment notes/page_files/image.png as it belongs to the attachment unit folder notes/page_files.');
      expect(warn).toHaveBeenCalledWith('Skipping renaming attachment notes/doc.html.p7s as it is a sidecar named after its base.');
      expect(warn).toHaveBeenCalledWith('Skipping renaming attachment notes/shared.png as it is referenced by multiple notes.\n- notes/note.md\n- other.md');
    });

    it('should rename an orphan sidecar, which has no base to follow', async () => {
      const orphan = linkAttachment('notes/lonely.p7s');
      mockGetRenamedAttachmentPath.mockResolvedValue('notes/file-1.p7s');
      await castTo<TestableHandler>(handler).executeAbstractFile(note);
      expect(mockRenameSafe).toHaveBeenCalledWith(expect.objectContaining({ oldPathOrAbstractFile: orphan }));
    });
  });
});
