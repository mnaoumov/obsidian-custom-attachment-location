import type {
  TAbstractFile,
  TFile
} from 'obsidian';
import type { ActiveFileProvider } from 'obsidian-dev-utils/obsidian/active-file-provider';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { isFile } from 'obsidian-dev-utils/obsidian/file-system';
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
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { CollectAttachmentsInFileCommandHandler } from './collect-attachments-in-file-command-handler.ts';

interface ActiveFileProviderHolder {
  _activeFileProvider: ActiveFileProvider;
}

interface TestableHandler {
  canExecute(): boolean;
  canExecuteAbstractFile(abstractFile: TAbstractFile): boolean;
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
  isFile: vi.fn()
}));

const mockCollectAttachmentsInAbstractFiles = vi.fn<AttachmentCollector['collectAttachmentsInAbstractFiles']>();
const mockIsFile = vi.mocked(isFile);
const mockIsNoteEx = vi.fn<PluginSettingsComponent['isNoteEx']>();

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

function createPluginSettingsComponent(): PluginSettingsComponent {
  return strictProxy<PluginSettingsComponent>({
    isNoteEx: (pathOrFile) => mockIsNoteEx(pathOrFile)
  });
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
  let pluginSettingsComponent: PluginSettingsComponent;

  beforeEach(() => {
    vi.clearAllMocks();
    attachmentCollector = createAttachmentCollector();
    pluginSettingsComponent = createPluginSettingsComponent();
    handler = new CollectAttachmentsInFileCommandHandler({ attachmentCollector, pluginSettingsComponent });
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(CollectAttachmentsInFileCommandHandler);
    expect(toTestable(handler).id).toBe('collect-attachments-in-file');
    expect(toTestable(handler).icon).toBe('download');
    expect(toTestable(handler).name).toBe('Collect attachments in current note');
  });

  describe('canExecuteAbstractFile', () => {
    it('should accept a note', () => {
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockReturnValue(true);
      expect(toTestable(handler).canExecuteAbstractFile(createAbstractFile('a.md'))).toBe(true);
    });

    it('should reject an attachment', () => {
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockReturnValue(false);
      expect(toTestable(handler).canExecuteAbstractFile(createAbstractFile('image.png'))).toBe(false);
    });

    /*
     * Issue #151. The predicate is `isNoteEx`, not the extension-based `isNote`, so a `.excalidraw.md`
     * — Markdown on disk, an attachment by the user's setting — is refused even though every plain
     * extension test would call it a note. The collector's walk skips it, so offering the command here
     * would offer one that silently does nothing.
     */
    it('should reject a drawing the user treats as an attachment', () => {
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockImplementation((pathOrFile) => castTo<TFile>(pathOrFile).path !== 'drawing.excalidraw.md');
      expect(toTestable(handler).canExecuteAbstractFile(createAbstractFile('drawing.excalidraw.md'))).toBe(false);
    });

    it('should accept a folder without asking the predicate, because the walk inside it filters', () => {
      mockIsFile.mockReturnValue(false);
      expect(toTestable(handler).canExecuteAbstractFile(createAbstractFile('folder'))).toBe(true);
      expect(mockIsNoteEx).not.toHaveBeenCalled();
    });
  });

  /*
   * The base composes the per-file predicate over every entry, and this handler no longer overrides that.
   * The cases below are here because the override it replaced was the ONLY gate the multi-select menu had,
   * so a future re-override has to keep answering them.
   */
  describe('canExecuteAbstractFiles', () => {
    it('should return true when all files are notes', () => {
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockReturnValue(true);
      expect(toTestable(handler).canExecuteAbstractFiles([createAbstractFile('a.md'), createAbstractFile('b.md')])).toBe(true);
    });

    it('should return false when one of the files is a drawing', () => {
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockImplementation((pathOrFile) => castTo<TFile>(pathOrFile).path !== 'drawing.excalidraw.md');
      expect(toTestable(handler).canExecuteAbstractFiles([createAbstractFile('a.md'), createAbstractFile('drawing.excalidraw.md')])).toBe(false);
    });
  });

  /*
   * The command-palette path, and the reason the gate moved onto the per-file predicate: `canExecute`
   * asks `canExecuteAbstractFile` about the ACTIVE file and never consults `canExecuteAbstractFiles`, so
   * while the gate lived only on the latter the palette offered this command on a drawing and it then did
   * nothing. Measured in `excalidraw-source-note-skip.desktop.integration.test.ts` against a real
   * Obsidian, through the same `checkCallback(true)` probe Obsidian uses to decide what to list.
   */
  describe('canExecute', () => {
    it('should refuse when no file is open', () => {
      setActiveFile(handler, null);
      expect(toTestable(handler).canExecute()).toBe(false);
    });

    it('should offer the command while a note is open', () => {
      setActiveFile(handler, createFile('active.md'));
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockReturnValue(true);
      expect(toTestable(handler).canExecute()).toBe(true);
    });

    it('should refuse while a drawing is open', () => {
      setActiveFile(handler, createFile('drawing.excalidraw.md'));
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockReturnValue(false);
      expect(toTestable(handler).canExecute()).toBe(false);
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
