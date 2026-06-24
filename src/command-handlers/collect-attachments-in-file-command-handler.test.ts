import type {
  TAbstractFile,
  TFile
} from 'obsidian';
import type { ActiveFileProvider } from 'obsidian-dev-utils/obsidian/active-file-provider';

import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  isFile,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentCollector } from '../attachment-collector.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { CollectAttachmentsInFileCommandHandler } from './collect-attachments-in-file-command-handler.ts';

interface ActiveFileProviderHolder {
  _activeFileProvider: ActiveFileProvider;
}

interface TestableHandler {
  canExecuteAbstractFiles(abstractFiles: TAbstractFile[]): boolean;
  executeAbstractFile(abstractFile: TAbstractFile): Promise<void>;
  executeAbstractFiles(abstractFiles: TAbstractFile[]): Promise<void>;
  icon: string;
  id: string;
  name: string;
  shouldAddToAbstractFileMenu(): boolean;
  shouldAddToAbstractFilesMenu(): boolean;
}

vi.mock('obsidian-dev-utils/obsidian/file-system', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/file-system')>(),
  isFile: vi.fn(),
  isNote: vi.fn()
}));

const mockCollectAttachmentsInAbstractFiles = vi.fn<AttachmentCollector['collectAttachmentsInAbstractFiles']>();
const mockIsFile = vi.mocked(isFile);
const mockIsNote = vi.mocked(isNote);

function createAbstractFile(path: string): TAbstractFile {
  return strictProxy<TAbstractFile>({ path });
}

function createAttachmentCollector(): AttachmentCollector {
  return strictProxy<AttachmentCollector>({
    collectAttachmentsInAbstractFiles: mockCollectAttachmentsInAbstractFiles
  });
}

function createFile(path: string): TFile {
  return strictProxy<TFile>({ path });
}

function setActiveFile(handler: CollectAttachmentsInFileCommandHandler, activeFile: null | TFile): void {
  castTo<ActiveFileProviderHolder>(handler)._activeFileProvider = strictProxy<ActiveFileProvider>({
    getActiveFile: () => activeFile
  });
}

function toTestable(handler: CollectAttachmentsInFileCommandHandler): TestableHandler {
  return castTo<TestableHandler>(handler);
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('CollectAttachmentsInFileCommandHandler', () => {
  let attachmentCollector: AttachmentCollector;
  let handler: CollectAttachmentsInFileCommandHandler;

  beforeEach(() => {
    vi.clearAllMocks();
    attachmentCollector = createAttachmentCollector();
    handler = new CollectAttachmentsInFileCommandHandler({ attachmentCollector });
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(CollectAttachmentsInFileCommandHandler);
    expect(toTestable(handler).id).toBe('collect-attachments-in-file');
    expect(toTestable(handler).icon).toBe('download');
    expect(toTestable(handler).name).toBe('Collect attachments in current note');
  });

  describe('canExecuteAbstractFiles', () => {
    it('should return false when the base canExecute returns false', () => {
      setActiveFile(handler, null);
      expect(toTestable(handler).canExecuteAbstractFiles([createAbstractFile('a.md')])).toBe(false);
      expect(mockIsFile).not.toHaveBeenCalled();
    });

    it('should return true when all files are notes', () => {
      setActiveFile(handler, createFile('active.md'));
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      expect(toTestable(handler).canExecuteAbstractFiles([createAbstractFile('a.md'), createAbstractFile('b.md')])).toBe(true);
    });

    it('should return false when one of the files is not a note', () => {
      setActiveFile(handler, createFile('active.md'));
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(false);
      expect(toTestable(handler).canExecuteAbstractFiles([createAbstractFile('image.png')])).toBe(false);
    });

    it('should return true when none of the abstract files are files', () => {
      setActiveFile(handler, createFile('active.md'));
      mockIsFile.mockReturnValue(false);
      expect(toTestable(handler).canExecuteAbstractFiles([createAbstractFile('folder')])).toBe(true);
      expect(mockIsNote).not.toHaveBeenCalled();
    });
  });

  describe('executeAbstractFile', () => {
    it('should delegate the single file wrapped in an array', async () => {
      const file = createAbstractFile('note.md');
      await toTestable(handler).executeAbstractFile(file);
      expect(mockCollectAttachmentsInAbstractFiles).toHaveBeenCalledExactlyOnceWith([file]);
    });
  });

  describe('executeAbstractFiles', () => {
    it('should delegate all files to the attachment collector', async () => {
      const files = [createAbstractFile('a.md'), createAbstractFile('b.md')];
      await toTestable(handler).executeAbstractFiles(files);
      expect(mockCollectAttachmentsInAbstractFiles).toHaveBeenCalledExactlyOnceWith(files);
    });
  });

  it('should add to the abstract file menu', () => {
    expect(toTestable(handler).shouldAddToAbstractFileMenu()).toBe(true);
  });

  it('should add to the abstract files menu', () => {
    expect(toTestable(handler).shouldAddToAbstractFilesMenu()).toBe(true);
  });
});
