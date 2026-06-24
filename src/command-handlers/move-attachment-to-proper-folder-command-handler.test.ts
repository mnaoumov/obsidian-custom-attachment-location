import type { CustomArrayDict } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  Reference,
  TAbstractFile,
  TFile,
  TFolder
} from 'obsidian';
import type { ActiveFileProvider } from 'obsidian-dev-utils/obsidian/active-file-provider';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';

import { Vault } from 'obsidian';
import { abortSignalAny } from 'obsidian-dev-utils/abort-controller';
import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  isFile,
  isFolder
} from 'obsidian-dev-utils/obsidian/file-system';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  editLinks,
  updateLink
} from 'obsidian-dev-utils/obsidian/link';
import { loop } from 'obsidian-dev-utils/obsidian/loop';
import { getBacklinksForFileSafe } from 'obsidian-dev-utils/obsidian/metadata-cache';
import { copySafe } from 'obsidian-dev-utils/obsidian/vault';
import { deleteIfNotUsed } from 'obsidian-dev-utils/obsidian/vault-delete';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { PluginSettings } from '../plugin-settings.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { selectMode } from '../modals/move-attachment-to-proper-folder-used-by-multiple-notes-modal.ts';
import { MoveAttachmentToProperFolderUsedByMultipleNotesMode } from '../plugin-settings.ts';
import { MoveAttachmentToProperFolderCommandHandler } from './move-attachment-to-proper-folder-command-handler.ts';

interface ActiveFileProviderHolder {
  _activeFileProvider: ActiveFileProvider;
}

interface LoopParams {
  readonly abortSignal: AbortSignal;
  buildNoticeMessage(item: TFile, iterationStr: string): string;
  readonly items: TFile[];
  processItem(item: TFile): Promise<void>;
  readonly progressBarTitle: string;
  readonly shouldContinueOnError: boolean;
  readonly shouldShowProgressBar: boolean;
}

interface PluginNameHolder {
  _pluginName: string;
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

vi.mock('obsidian-dev-utils/abort-controller', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/abort-controller')>(),
  abortSignalAny: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/file-system', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/file-system')>(),
  isFile: vi.fn(),
  isFolder: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/link', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/link')>(),
  editLinks: vi.fn(),
  updateLink: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/loop', () => ({
  loop: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/metadata-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/metadata-cache')>(),
  getBacklinksForFileSafe: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/vault', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/vault')>(),
  copySafe: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/vault-delete', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/vault-delete')>(),
  deleteIfNotUsed: vi.fn()
}));

vi.mock('../modals/move-attachment-to-proper-folder-used-by-multiple-notes-modal.ts', () => ({
  selectMode: vi.fn()
}));

const mockAbortSignalAny = vi.mocked(abortSignalAny);
const mockCopySafe = vi.mocked(copySafe);
const mockDeleteIfNotUsed = vi.mocked(deleteIfNotUsed);
const mockEditLinks = vi.mocked(editLinks);
const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);
const mockIsFile = vi.mocked(isFile);
const mockIsFolder = vi.mocked(isFolder);
const mockLoop = vi.mocked(loop);
const mockSelectMode = vi.mocked(selectMode);
const mockUpdateLink = vi.mocked(updateLink);

const mockGetProperAttachmentPath = vi.fn<AttachmentPathManager['getProperAttachmentPath']>();
const mockIsNoteEx = vi.fn<PluginSettingsComponent['isNoteEx']>();
const mockIsPathIgnored = vi.fn<PluginSettings['isPathIgnored']>();

function createBacklinks(map: Map<string, Reference[]>): CustomArrayDict<Reference> {
  return strictProxy<CustomArrayDict<Reference>>({
    get(key: string): null | Reference[] {
      return map.get(key) ?? null;
    },
    keys(): string[] {
      return Array.from(map.keys());
    }
  });
}

function createFile(path: string): TFile {
  return strictProxy<TFile>({ path });
}

function createFolder(path: string): TFolder {
  return strictProxy<TFolder>({ path });
}

function createReference(original: string): Reference {
  return strictProxy<Reference>({ link: original, original });
}

function getLoopParams(): LoopParams {
  return castTo<LoopParams>(mockLoop.mock.calls[0]?.[0]);
}

function setActiveFile(handler: MoveAttachmentToProperFolderCommandHandler, activeFile: null | TFile): void {
  castTo<ActiveFileProviderHolder>(handler)._activeFileProvider = strictProxy<ActiveFileProvider>({
    getActiveFile: () => activeFile
  });
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('MoveAttachmentToProperFolderCommandHandler', () => {
  let abortSignalComponent: AbortSignalComponent;
  let app: App;
  let attachmentPathManager: AttachmentPathManager;
  let combinedAbortSignal: AbortSignal;
  let getFileByPath: ReturnType<typeof vi.fn<(path: string) => null | TFile>>;
  let handler: MoveAttachmentToProperFolderCommandHandler;
  let mode: MoveAttachmentToProperFolderUsedByMultipleNotesMode;
  let pluginSettingsComponent: PluginSettingsComponent;

  beforeEach(() => {
    vi.clearAllMocks();
    mockIsPathIgnored.mockReturnValue(false);
    mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
    combinedAbortSignal = new AbortController().signal;
    mockAbortSignalAny.mockReturnValue(combinedAbortSignal);
    mockUpdateLink.mockReturnValue('new-link');
    getFileByPath = vi.fn<(path: string) => null | TFile>();
    app = strictProxy<App>({
      vault: strictProxy<App['vault']>({
        getFileByPath: (path: string) => getFileByPath(path)
      })
    });
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      isNoteEx: mockIsNoteEx,
      settings: strictProxy<PluginSettings>({
        isPathIgnored: mockIsPathIgnored,
        get moveAttachmentToProperFolderUsedByMultipleNotesMode(): MoveAttachmentToProperFolderUsedByMultipleNotesMode {
          return mode;
        }
      })
    });
    abortSignalComponent = strictProxy<AbortSignalComponent>({
      abortSignal: new AbortController().signal
    });
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getProperAttachmentPath: mockGetProperAttachmentPath
    });
    handler = new MoveAttachmentToProperFolderCommandHandler({
      abortSignalComponent,
      app,
      attachmentPathManager,
      pluginSettingsComponent
    });
    castTo<PluginNameHolder>(handler)._pluginName = 'My Plugin';
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(MoveAttachmentToProperFolderCommandHandler);
    expect(castTo<TestableHandler>(handler).id).toBe('move-attachment-to-proper-folder');
    expect(castTo<TestableHandler>(handler).icon).toBe('move');
    expect(castTo<TestableHandler>(handler).name).toBe('Move attachment to proper folder');
  });

  describe('canExecuteAbstractFiles', () => {
    it('should return false when the base canExecute returns false', () => {
      setActiveFile(handler, null);
      expect(castTo<TestableHandler>(handler).canExecuteAbstractFiles([createFile('a.png')])).toBe(false);
    });

    it('should return false when a file is a note', () => {
      setActiveFile(handler, createFile('active.md'));
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockReturnValueOnce(false).mockReturnValueOnce(true);
      const files = [createFile('image.png'), createFile('note.md')];
      expect(castTo<TestableHandler>(handler).canExecuteAbstractFiles(files)).toBe(false);
    });

    it('should return true when no file is a note', () => {
      setActiveFile(handler, createFile('active.md'));
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockReturnValue(false);
      expect(castTo<TestableHandler>(handler).canExecuteAbstractFiles([createFile('a.png'), createFile('b.png')])).toBe(true);
    });

    it('should return true when none of the abstract files are files', () => {
      setActiveFile(handler, createFile('active.md'));
      mockIsFile.mockReturnValue(false);
      expect(castTo<TestableHandler>(handler).canExecuteAbstractFiles([createFolder('folder1'), createFolder('folder2')])).toBe(true);
      expect(mockIsNoteEx).not.toHaveBeenCalled();
    });
  });

  it('should add to the abstract file menu', () => {
    expect(castTo<TestableHandler>(handler).shouldAddToAbstractFileMenu()).toBe(true);
  });

  it('should add to the abstract files menu', () => {
    expect(castTo<TestableHandler>(handler).shouldAddToAbstractFilesMenu()).toBe(true);
  });

  describe('executeAbstractFile', () => {
    it('should delegate to executeAbstractFiles with the single file', async () => {
      mockIsFile.mockReturnValue(true);
      mockIsNoteEx.mockReturnValue(false);
      mockLoop.mockResolvedValue();
      const file = createFile('image.png');
      await castTo<TestableHandler>(handler).executeAbstractFile(file);
      expect(getLoopParams().items).toEqual([file]);
    });
  });

  describe('executeAbstractFiles', () => {
    it('should collect attachment files, recurse folders, sort, and pass them to loop', async () => {
      const attachmentA = createFile('z-a.png');
      const attachmentB = createFile('a-b.png');
      const note = createFile('note.md');
      const childAttachment = createFile('folder/child.png');
      const childNote = createFile('folder/child.md');
      const folder = createFolder('folder');

      mockIsFile.mockImplementation((value) => {
        const path = castTo<TAbstractFile>(value).path;
        return path.endsWith('.png') || path.endsWith('.md');
      });
      mockIsFolder.mockImplementation((value) => castTo<TAbstractFile>(value) === folder);
      mockIsNoteEx.mockImplementation((value) => castTo<TAbstractFile>(value).path.endsWith('.md'));
      vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, cb) => {
        cb(childAttachment);
        cb(childNote);
      });
      mockLoop.mockResolvedValue();

      await castTo<TestableHandler>(handler).executeAbstractFiles([attachmentA, attachmentB, note, folder]);

      const params = getLoopParams();
      expect(params.items.map((file) => file.path)).toEqual(['a-b.png', 'folder/child.png', 'z-a.png']);
      expect(params.buildNoticeMessage(attachmentA, '1/3')).toBe('Moving attachment to proper folder 1/3 - \'z-a.png\'.');
      expect(params.progressBarTitle).toBe('My Plugin: Moving attachment to proper folder...');
    });

    it('should warn and skip processing when the attachment path is ignored', async () => {
      const attachment = createFile('ignored.png');
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mockIsPathIgnored.mockReturnValue(true);
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });

      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);

      expect(warnSpy).toHaveBeenCalledExactlyOnceWith('Cannot move attachment to proper folder as attachment path is ignored: ignored.png.');
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
      warnSpy.mockRestore();
    });

    it('should return early from processItem when moveAttachmentToProperFolder returns false', async () => {
      const attachment = createFile('attachment.png');
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel;
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(
        new Map([
          ['note1.md', [createReference('[[attachment]]')]],
          ['note2.md', [createReference('[[attachment]]')]]
        ])
      ));
      mockSelectMode.mockResolvedValue({
        backlinksToCopy: [],
        mode: MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel,
        shouldUseSameActionForOtherProblematicAttachments: false
      });
      const throwIfAbortedSpy = vi.spyOn(combinedAbortSignal, 'throwIfAborted').mockImplementation(() => undefined);
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });

      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);

      expect(mockSelectMode).toHaveBeenCalledExactlyOnceWith(app, 'attachment.png', ['note1.md', 'note2.md'], true);
      throwIfAbortedSpy.mockRestore();
    });
  });

  describe('moveAttachmentToProperFolder', () => {
    async function runProcessItem(attachment: TFile): Promise<void> {
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });
      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);
    }

    it('should stop after notifying when the attachment has no backlinks', async () => {
      const attachment = createFile('unused.png');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(new Map()));

      await runProcessItem(attachment);

      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledOnce();
      expect(mockCopySafe).not.toHaveBeenCalled();
      expect(mockDeleteIfNotUsed).not.toHaveBeenCalled();
    });

    it('should not copy for a single backlink (handleMode is not invoked)', async () => {
      const attachment = createFile('attachment.png');
      const reference = createReference('[[attachment]]');
      const backlinkFile = createFile('note1.md');
      mockGetBacklinksForFileSafe
        .mockResolvedValueOnce(createBacklinks(new Map([['note1.md', [reference]]])))
        .mockResolvedValueOnce(createBacklinks(new Map([['note1.md', [reference]]])));
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
      getFileByPath.mockReturnValue(backlinkFile);
      mockGetProperAttachmentPath.mockResolvedValue('new-folder/attachment.png');
      mockEditLinks.mockResolvedValue();

      await runProcessItem(attachment);

      expect(mockCopySafe).not.toHaveBeenCalled();
      expect(mockDeleteIfNotUsed).not.toHaveBeenCalled();
    });

    it('should copy attachment, update matching links, and delete when no backlinks remain (CopyAll)', async () => {
      const attachment = createFile('attachment.png');
      const reference = createReference('[[attachment]]');
      const backlinkFile = createFile('note1.md');
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
      mockGetBacklinksForFileSafe
        .mockResolvedValueOnce(createBacklinks(
          new Map([
            ['note1.md', [reference]],
            ['note2.md', [createReference('[[attachment]]2')]]
          ])
        ))
        .mockResolvedValueOnce(createBacklinks(new Map()));
      getFileByPath.mockImplementation((path) => path === 'note1.md' ? backlinkFile : null);
      mockGetProperAttachmentPath.mockResolvedValue('new-folder/attachment.png');
      mockEditLinks.mockImplementation(async (_app, _file, converter) => {
        await converter(reference);
        await converter(createReference('non-matching'));
      });
      mockDeleteIfNotUsed.mockResolvedValue(true);
      mockCopySafe.mockResolvedValue('new-folder/attachment.png');

      await runProcessItem(attachment);

      expect(mockCopySafe).toHaveBeenCalledExactlyOnceWith(app, attachment, 'new-folder/attachment.png');
      expect(mockUpdateLink).toHaveBeenCalledOnce();
      expect(mockDeleteIfNotUsed).toHaveBeenCalledExactlyOnceWith(app, attachment);
    });

    it('should skip a backlink whose file cannot be resolved (CopyAll)', async () => {
      const attachment = createFile('attachment.png');
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
      mockGetBacklinksForFileSafe
        .mockResolvedValueOnce(createBacklinks(
          new Map([
            ['missing.md', [createReference('[[attachment]]')]],
            ['other.md', [createReference('[[attachment]]')]]
          ])
        ))
        .mockResolvedValueOnce(createBacklinks(new Map([['other.md', [createReference('[[attachment]]')]]])));
      getFileByPath.mockReturnValue(null);

      await runProcessItem(attachment);

      expect(mockCopySafe).not.toHaveBeenCalled();
      expect(mockDeleteIfNotUsed).not.toHaveBeenCalled();
    });

    it('should skip a backlink whose first reference is missing (CopyAll)', async () => {
      const attachment = createFile('attachment.png');
      const backlinkFile = createFile('note1.md');
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
      mockGetBacklinksForFileSafe
        .mockResolvedValueOnce(createBacklinks(
          new Map([
            ['note1.md', []],
            ['note2.md', [createReference('[[attachment]]')]]
          ])
        ))
        .mockResolvedValueOnce(createBacklinks(new Map([['note2.md', [createReference('[[attachment]]')]]])));
      getFileByPath.mockImplementation((path) => path === 'note1.md' ? backlinkFile : null);

      await runProcessItem(attachment);

      expect(mockCopySafe).not.toHaveBeenCalled();
    });

    it('should skip a backlink when the attachment is already in the destination folder (CopyAll)', async () => {
      const attachment = createFile('attachment.png');
      const backlinkFile = createFile('note1.md');
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
      mockGetBacklinksForFileSafe
        .mockResolvedValueOnce(createBacklinks(
          new Map([
            ['note1.md', [createReference('[[attachment]]')]],
            ['note2.md', [createReference('[[attachment]]')]]
          ])
        ))
        .mockResolvedValueOnce(createBacklinks(new Map([['note2.md', [createReference('[[attachment]]')]]])));
      getFileByPath.mockReturnValue(backlinkFile);
      mockGetProperAttachmentPath.mockResolvedValue(null);
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

      await runProcessItem(attachment);

      expect(warnSpy).toHaveBeenCalledWith('Skipping moving attachment attachment.png to proper folder as it is already in the destination folder.');
      expect(mockCopySafe).not.toHaveBeenCalled();
      warnSpy.mockRestore();
    });
  });

  describe('handleMode', () => {
    async function runWithMode(selectedMode: MoveAttachmentToProperFolderUsedByMultipleNotesMode): Promise<void> {
      const attachment = createFile('attachment.png');
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mode = selectedMode;
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(
        new Map([
          ['note1.md', [createReference('[[a]]')]],
          ['note2.md', [createReference('[[a]]')]]
        ])
      ));
      getFileByPath.mockReturnValue(null);
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });
      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);
    }

    it('should select cancel mode when settings default is Cancel', async () => {
      await runWithMode(MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel);
      expect(mockSelectMode).toHaveBeenCalledExactlyOnceWith(app, 'attachment.png', ['note1.md', 'note2.md'], true);
    });

    it('should not re-prompt for Cancel mode when settings default is not Cancel', async () => {
      const attachment = createFile('attachment.png');
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt;
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(
        new Map([
          ['note1.md', [createReference('[[a]]')]],
          ['note2.md', [createReference('[[a]]')]]
        ])
      ));
      mockSelectMode.mockResolvedValue({
        backlinksToCopy: [],
        mode: MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel,
        shouldUseSameActionForOtherProblematicAttachments: false
      });
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });

      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);

      expect(mockSelectMode).toHaveBeenCalledExactlyOnceWith(app, 'attachment.png', ['note1.md', 'note2.md']);
      expect(mockCopySafe).not.toHaveBeenCalled();
    });

    it('should copy all backlinks for CopyAll mode', async () => {
      const attachment = createFile('attachment.png');
      const backlinkFile = createFile('note1.md');
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
      const reference = createReference('[[a]]');
      mockGetBacklinksForFileSafe
        .mockResolvedValueOnce(createBacklinks(
          new Map([
            ['note1.md', [reference]],
            ['note2.md', [createReference('[[a]]2')]]
          ])
        ))
        .mockResolvedValueOnce(createBacklinks(new Map([['note2.md', [createReference('[[a]]2')]]])));
      getFileByPath.mockImplementation((path) => path === 'note1.md' ? backlinkFile : null);
      mockGetProperAttachmentPath.mockResolvedValue('new/attachment.png');
      mockEditLinks.mockResolvedValue();
      mockCopySafe.mockResolvedValue('new/attachment.png');
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });

      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);

      expect(mockCopySafe).toHaveBeenCalledExactlyOnceWith(app, attachment, 'new/attachment.png');
    });

    it('should use the prompt result backlinks when prompt resolves to Prompt mode', async () => {
      const attachment = createFile('attachment.png');
      const backlinkFile = createFile('note1.md');
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt;
      const reference = createReference('[[a]]');
      mockGetBacklinksForFileSafe
        .mockResolvedValueOnce(createBacklinks(
          new Map([
            ['note1.md', [reference]],
            ['note2.md', [createReference('[[a]]2')]]
          ])
        ))
        .mockResolvedValueOnce(createBacklinks(new Map([['note2.md', [createReference('[[a]]2')]]])));
      mockSelectMode.mockResolvedValue({
        backlinksToCopy: ['note1.md'],
        mode: MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt,
        shouldUseSameActionForOtherProblematicAttachments: true
      });
      getFileByPath.mockImplementation((path) => path === 'note1.md' ? backlinkFile : null);
      mockGetProperAttachmentPath.mockResolvedValue('new/attachment.png');
      mockEditLinks.mockResolvedValue();
      mockCopySafe.mockResolvedValue('new/attachment.png');
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });

      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);

      expect(mockSelectMode).toHaveBeenCalledExactlyOnceWith(app, 'attachment.png', ['note1.md', 'note2.md']);
      expect(mockCopySafe).toHaveBeenCalledExactlyOnceWith(app, attachment, 'new/attachment.png');
    });

    it('should recurse into the resolved mode when prompt resolves to CopyAll', async () => {
      const attachment = createFile('attachment.png');
      const backlinkFile = createFile('note1.md');
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt;
      const reference = createReference('[[a]]');
      mockGetBacklinksForFileSafe
        .mockResolvedValueOnce(createBacklinks(
          new Map([
            ['note1.md', [reference]],
            ['note2.md', [createReference('[[a]]2')]]
          ])
        ))
        .mockResolvedValueOnce(createBacklinks(new Map([['note2.md', [createReference('[[a]]2')]]])));
      mockSelectMode.mockResolvedValue({
        backlinksToCopy: [],
        mode: MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll,
        shouldUseSameActionForOtherProblematicAttachments: false
      });
      getFileByPath.mockImplementation((path) => path === 'note1.md' ? backlinkFile : null);
      mockGetProperAttachmentPath.mockResolvedValue('new/attachment.png');
      mockEditLinks.mockResolvedValue();
      mockCopySafe.mockResolvedValue('new/attachment.png');
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });

      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);

      expect(mockCopySafe).toHaveBeenCalledExactlyOnceWith(app, attachment, 'new/attachment.png');
    });

    it('should copy nothing for Skip mode', async () => {
      await runWithMode(MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip);
      expect(mockCopySafe).not.toHaveBeenCalled();
    });

    it('should return false for an unknown mode (default branch)', async () => {
      const attachment = createFile('attachment.png');
      mockIsFile.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      mockIsNoteEx.mockReturnValue(false);
      mode = castTo<MoveAttachmentToProperFolderUsedByMultipleNotesMode>('UnknownMode');
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(
        new Map([
          ['note1.md', [createReference('[[a]]')]],
          ['note2.md', [createReference('[[a]]')]]
        ])
      ));
      mockLoop.mockImplementation(async (params) => {
        await castTo<LoopParams>(params).processItem(attachment);
      });

      await castTo<TestableHandler>(handler).executeAbstractFiles([attachment]);

      expect(mockCopySafe).not.toHaveBeenCalled();
    });
  });
});
