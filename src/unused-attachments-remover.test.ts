import type { CustomArrayDict } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  Reference,
  TAbstractFile,
  TFile,
  TFolder
} from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { CachedMetadataEx } from 'obsidian-dev-utils/obsidian/metadata-cache';
import type {
  Mock,
  MockInstance
} from 'vitest';

import { Vault } from 'obsidian';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { getCanvasReferences } from 'obsidian-dev-utils/obsidian/canvas';
import { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import {
  isCanvasFile,
  isFile,
  isFolder,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { extractLinkFile } from 'obsidian-dev-utils/obsidian/link';
import {
  getBacklinksForFileSafe,
  getCacheSafe,
  getLinks
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { confirm } from 'obsidian-dev-utils/obsidian/modals/confirm';
import { addToQueue } from 'obsidian-dev-utils/obsidian/queue';
import {
  cleanupEmptyFolders,
  trashSafe
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

import { translationsMap } from './i18n/locales/translations-map.ts';
import { UnusedAttachmentsRemover } from './unused-attachments-remover.ts';

interface QueueParamsLike {
  operationFunction(abortSignal: AbortSignal): Promise<void>;
  operationName: string;
}

interface SettingsLike {
  emptyFolderBehavior: EmptyFolderBehavior;
  getTimeoutInMilliseconds(): number;
  isExcludedFromMultipleNotesCheck(path: string): boolean;
  isPathIgnored(path: string): boolean;
}

vi.mock('obsidian-dev-utils/obsidian/canvas', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/canvas')>(),
  getCanvasReferences: vi.fn()
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
  extractLinkFile: vi.fn()
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
  trashSafe: vi.fn()
}));

const mockGetCanvasReferences = vi.mocked(getCanvasReferences);
const mockIsCanvasFile = vi.mocked(isCanvasFile);
const mockIsFile = vi.mocked(isFile);
const mockIsFolder = vi.mocked(isFolder);
const mockIsNote = vi.mocked(isNote);
const mockExtractLinkFile = vi.mocked(extractLinkFile);
const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);
const mockGetCacheSafe = vi.mocked(getCacheSafe);
const mockGetLinks = vi.mocked(getLinks);
const mockConfirm = vi.mocked(confirm);
const mockAddToQueue = vi.mocked(addToQueue);
const mockCleanupEmptyFolders = vi.mocked(cleanupEmptyFolders);
const mockTrashSafe = vi.mocked(trashSafe);

const PLUGIN_NAME = 'Custom Attachment Location';
const ATTACHMENT_FOLDER_PATH = 'assets/note';

interface ConfirmParamsLike {
  message: DocumentFragment;
}

function createBacklinks(keys: string[]): CustomArrayDict<Reference> {
  return strictProxy<CustomArrayDict<Reference>>({
    keys: () => keys
  });
}

function createFile(path: string): TFile {
  return strictProxy<TFile>({
    name: path.split('/').at(-1) ?? '',
    path
  });
}

let vaultRootFolder: TFolder;

function createFolder(path: string): TFolder {
  return strictProxy<TFolder>({
    name: path.split('/').at(-1) ?? '',
    path
  });
}

function createReference(link: string): Reference {
  return strictProxy<Reference>({
    link,
    original: `![[${link}]]`
  });
}

function getConfirmMessageText(): string {
  return castTo<ConfirmParamsLike>(mockConfirm.mock.calls[0]?.[0]).message.textContent;
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('UnusedAttachmentsRemover', () => {
  let abortSignalComponent: AbortSignalComponent;
  let app: App;
  let attachmentFolder: TFolder;
  let attachmentPathManager: AttachmentPathManager;
  let getAttachmentFolderFullPathForPath: Mock<AttachmentPathManager['getAttachmentFolderFullPathForPath']>;
  let getFolderByPath: Mock<(path: string) => null | TFolder>;
  let pluginNoticeComponent: PluginNoticeComponent;
  let pluginSettingsComponent: PluginSettingsComponent;
  let remover: UnusedAttachmentsRemover;
  let settings: SettingsLike;
  let showNoticeSpy: Mock;
  let warnSpy: MockInstance<typeof console.warn>;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = {
      emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
      getTimeoutInMilliseconds: vi.fn<() => number>().mockReturnValue(1000),
      isExcludedFromMultipleNotesCheck: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      isPathIgnored: vi.fn<(path: string) => boolean>().mockReturnValue(false)
    };
    attachmentFolder = strictProxy<TFolder>({ children: [], path: ATTACHMENT_FOLDER_PATH });
    getFolderByPath = vi.fn<(path: string) => null | TFolder>().mockReturnValue(attachmentFolder);
    app = strictProxy<App>({
      vault: strictProxy<App['vault']>({
        getFolderByPath: (path: string) => getFolderByPath(path),
        getRoot: () => vaultRootFolder
      })
    });
    vaultRootFolder = createFolder('/');
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      isNoteEx: vi.fn<PluginSettingsComponent['isNoteEx']>().mockReturnValue(false),
      settings: castTo<PluginSettings>(settings)
    });
    getAttachmentFolderFullPathForPath = vi.fn<AttachmentPathManager['getAttachmentFolderFullPathForPath']>().mockResolvedValue(ATTACHMENT_FOLDER_PATH);
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getAttachmentFolderFullPathForPath: (params) => getAttachmentFolderFullPathForPath(params)
    });
    abortSignalComponent = strictProxy<AbortSignalComponent>({
      abortSignal: new AbortController().signal
    });
    pluginNoticeComponent = new PluginNoticeComponent({ app, pluginName: PLUGIN_NAME });
    showNoticeSpy = vi.fn();
    vi.spyOn(pluginNoticeComponent, 'showNotice').mockImplementation((...$arguments) => castTo<PluginNoticeComponent['showNotice']>(showNoticeSpy)(...$arguments));
    remover = new UnusedAttachmentsRemover({
      abortSignalComponent,
      app,
      attachmentPathManager,
      pluginName: PLUGIN_NAME,
      pluginNoticeComponent,
      pluginSettingsComponent
    });
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  async function runOperation(abstractFiles: TAbstractFile[], abortSignal = new AbortController().signal): Promise<void> {
    remover.deleteUnusedAttachmentsInAbstractFiles(abstractFiles);
    const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
    await params.operationFunction(abortSignal);
  }

  describe('deleteUnusedAttachmentsInAbstractFiles', () => {
    it('should enqueue an operation for the given files', () => {
      remover.deleteUnusedAttachmentsInAbstractFiles([createFile('note.md')]);
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      expect(params.operationName).toBe('Delete unused attachments in file');
    });

    it('should throw when the signal is already aborted', async () => {
      const controller = new AbortController();
      controller.abort();
      await expect(runOperation([], controller.signal)).rejects.toThrow();
    });
  });

  describe('gathering note files', () => {
    it('should skip a single file that is not a note', async () => {
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(false);
      mockIsFolder.mockReturnValue(false);
      await runOperation([createFile('image.png')]);
      expect(mockGetCacheSafe).not.toHaveBeenCalled();
      expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('No unused attachments found.');
    });

    it('should collect notes from files and recurse folders (skipping non-note children)', async () => {
      const note = createFile('note.md');
      const folder = strictProxy<TAbstractFile>({ path: 'folder' });
      const childNote = createFile('folder/child.md');
      const childNonNote = createFile('folder/img.png');
      mockIsFile.mockImplementation((f) => f !== folder);
      mockIsFolder.mockImplementation((f) => f === folder);
      mockIsNote.mockImplementation((f) => f === note || f === childNote);
      mockGetCacheSafe.mockResolvedValue(null);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((root, callback) => {
        if (root !== folder) {
          return;
        }

        callback(childNote);
        callback(childNonNote);
      });
      try {
        await runOperation([note, folder]);
      } finally {
        recurseSpy.mockRestore();
      }
      // Both real notes are scanned; the non-note child is not.
      expect(mockGetCacheSafe).toHaveBeenCalledTimes(2);
      expect(mockGetCacheSafe).toHaveBeenCalledWith(app, note);
      expect(mockGetCacheSafe).toHaveBeenCalledWith(app, childNote);
    });

    it('should skip an ignored note without scanning it', async () => {
      const note = createFile('note.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockReturnValue(true);
      mockIsFolder.mockReturnValue(false);
      vi.mocked(settings.isPathIgnored).mockReturnValue(true);
      await runOperation([note]);
      expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('note path is ignored'));
      expect(mockGetCacheSafe).not.toHaveBeenCalled();
      expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('No unused attachments found.');
    });
  });

  describe('findUnusedAttachments', () => {
    let note: TFile;

    beforeEach(() => {
      note = createFile('note.md');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockImplementation((f) => f === note);
      mockIsFolder.mockReturnValue(false);
      mockIsCanvasFile.mockReturnValue(false);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([]);
    });

    it('should skip a note without a cache', async () => {
      mockGetCacheSafe.mockResolvedValue(null);
      await runOperation([note]);
      expect(mockGetLinks).not.toHaveBeenCalled();
      expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('No unused attachments found.');
    });

    it('should read references from a canvas note', async () => {
      mockIsCanvasFile.mockReturnValue(true);
      mockGetCanvasReferences.mockResolvedValue([]);
      await runOperation([note]);
      expect(mockGetCanvasReferences).toHaveBeenCalledWith(app, note);
      expect(mockGetLinks).not.toHaveBeenCalled();
    });

    it('should ignore a reference that cannot be resolved to a file', async () => {
      mockGetLinks.mockReturnValue([createReference('missing.png')]);
      mockExtractLinkFile.mockReturnValue(null);
      const orphan = createFile(`${ATTACHMENT_FOLDER_PATH}/orphan.png`);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        callback(orphan);
      });
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks([]));
      mockConfirm.mockResolvedValue(true);
      try {
        await runOperation([note]);
      } finally {
        recurseSpy.mockRestore();
      }
      // The unresolved reference does not protect any file, so the orphan is trashed.
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, orphan);
    });

    it('should return nothing when the attachment folder does not exist', async () => {
      getFolderByPath.mockReturnValue(null);
      await runOperation([note]);
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
      expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('No unused attachments found.');
    });

    it('should skip folder children that are not files, are notes, or are still referenced', async () => {
      const referenced = createFile(`${ATTACHMENT_FOLDER_PATH}/referenced.png`);
      const noteInFolder = createFile(`${ATTACHMENT_FOLDER_PATH}/inner.md`);
      const subFolder = strictProxy<TAbstractFile>({ path: `${ATTACHMENT_FOLDER_PATH}/sub` });
      const unused = createFile(`${ATTACHMENT_FOLDER_PATH}/unused.png`);
      mockGetLinks.mockReturnValue([createReference('referenced.png')]);
      mockExtractLinkFile.mockReturnValue(referenced);
      mockIsFile.mockImplementation((f) => f !== subFolder);
      mockIsNote.mockImplementation((f) => f === note);
      vi.mocked(pluginSettingsComponent.isNoteEx).mockImplementation((f) => f === noteInFolder);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        callback(subFolder);
        callback(noteInFolder);
        callback(referenced);
        callback(unused);
      });
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks([]));
      mockConfirm.mockResolvedValue(true);
      try {
        await runOperation([note]);
      } finally {
        recurseSpy.mockRestore();
      }
      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledExactlyOnceWith({
        app,
        pathOrFile: unused,
        timeoutInMilliseconds: 1000
      });
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, unused);
    });

    it('should keep an attachment still referenced by another non-excluded note', async () => {
      const shared = createFile(`${ATTACHMENT_FOLDER_PATH}/shared.png`);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        callback(shared);
      });
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['other.md']));
      try {
        await runOperation([note]);
      } finally {
        recurseSpy.mockRestore();
      }
      expect(mockTrashSafe).not.toHaveBeenCalled();
      expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('No unused attachments found.');
    });

    it('should trash an attachment whose only backlinks are the note itself and excluded notes', async () => {
      const unused = createFile(`${ATTACHMENT_FOLDER_PATH}/unused.png`);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        callback(unused);
      });
      // `note.md` is the source note (self-reference) and `drawing.excalidraw.md` is excluded, so the
      // Effective backlink count is zero and the attachment is treated as unused.
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'drawing.excalidraw.md']));
      vi.mocked(settings.isExcludedFromMultipleNotesCheck).mockImplementation((path) => path === 'drawing.excalidraw.md');
      mockConfirm.mockResolvedValue(true);
      try {
        await runOperation([note]);
      } finally {
        recurseSpy.mockRestore();
      }
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, unused);
    });
  });

  describe('confirmation and trashing', () => {
    let note: TFile;
    let unusedA: TFile;
    let unusedB: TFile;

    beforeEach(() => {
      note = createFile('note.md');
      unusedA = createFile(`${ATTACHMENT_FOLDER_PATH}/a.png`);
      unusedB = createFile('other-folder/b.png');
      mockIsFile.mockReturnValue(true);
      mockIsNote.mockImplementation((f) => f === note);
      mockIsFolder.mockReturnValue(false);
      mockIsCanvasFile.mockReturnValue(false);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([]);
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks([]));
      vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        callback(unusedA);
        callback(unusedB);
      });
    });

    it('should trash the confirmed attachments and clean up their folders', async () => {
      mockConfirm.mockResolvedValue(true);
      await runOperation([note]);
      expect(mockTrashSafe).toHaveBeenCalledTimes(2);
      expect(mockTrashSafe).toHaveBeenCalledWith(app, unusedA);
      expect(mockTrashSafe).toHaveBeenCalledWith(app, unusedB);
      expect(mockCleanupEmptyFolders).toHaveBeenCalledExactlyOnceWith({
        app,
        emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
        folderPaths: [ATTACHMENT_FOLDER_PATH, 'other-folder']
      });
    });

    it('should not trash anything when the confirmation is declined', async () => {
      mockConfirm.mockResolvedValue(false);
      await runOperation([note]);
      expect(mockTrashSafe).not.toHaveBeenCalled();
      expect(mockCleanupEmptyFolders).not.toHaveBeenCalled();
    });

    it('should state the count in the confirmation', async () => {
      mockConfirm.mockResolvedValue(false);
      await runOperation([note]);
      expect(getConfirmMessageText()).toContain('2 attachment(s) will be moved to the trash.');
    });

    it('should list every path while there are few of them', async () => {
      mockConfirm.mockResolvedValue(false);
      await runOperation([note]);
      const text = getConfirmMessageText();
      expect(text).toContain(unusedA.path);
      expect(text).toContain(unusedB.path);
      expect(text).not.toContain('... and');
    });

    it('should cap the list and summarize the rest', async () => {
      // Vault-wide this dialog can be handed thousands of paths; an unbounded list is a wall the user
      // Scrolls past rather than a safety check.
      const many = Array.from({ length: 60 }, (_unused, index) => createFile(`${ATTACHMENT_FOLDER_PATH}/many-${index.toString().padStart(2, '0')}.png`));
      vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        for (const file of many) {
          callback(file);
        }
      });
      mockConfirm.mockResolvedValue(false);
      await runOperation([note]);

      const text = getConfirmMessageText();
      expect(text).toContain('60 attachment(s) will be moved to the trash.');
      expect(text).toContain('... and 10 more.');
      expect(text).toContain(many[0]?.path ?? '');
      expect(text).not.toContain(many[59]?.path ?? '');
    });
  });

  describe('deleteUnusedAttachmentsEntireVault', () => {
    it('should enqueue an operation over the vault root under its own name', () => {
      remover.deleteUnusedAttachmentsEntireVault();
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      expect(params.operationName).toBe('Delete unused attachments in entire vault');
    });

    it('should scan every note in the vault', async () => {
      const rootFolder = vaultRootFolder;
      const note = createFile('deep/note.md');
      mockIsFile.mockImplementation((f) => f === note);
      mockIsNote.mockReturnValue(true);
      mockIsFolder.mockImplementation((f) => f === rootFolder);
      mockGetCacheSafe.mockResolvedValue(null);
      vi.spyOn(Vault, 'recurseChildren').mockImplementation((root, callback) => {
        if (root === rootFolder) {
          callback(note);
        }
      });

      remover.deleteUnusedAttachmentsEntireVault();
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      await params.operationFunction(new AbortController().signal);

      expect(mockGetCacheSafe).toHaveBeenCalledWith(app, note);
    });
  });
});
