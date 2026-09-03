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
import type { CanvasReference } from 'obsidian-dev-utils/obsidian/reference';
import type {
  Mock,
  MockInstance
} from 'vitest';

import { Vault } from 'obsidian';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { getCanvasReferences } from 'obsidian-dev-utils/obsidian/canvas';
import { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
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
  EmptyFolderBehavior,
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

import type { HandedOverSettings } from './advanced-rename-and-delete-handler.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { AttachmentUnitFolderDesignation } from './attachment-unit-folder-designation.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
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
  isAttachmentUnitFolder(path: string): boolean;
  isExcludedFromMultipleNotesCheck(path: string): boolean;
  isOrphanAttachmentScanCandidate(path: string): boolean;
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

/**
 * Builds the patched vault method the remover reads the attachment-unit-folder designation off.
 *
 * The remover consults the published answer rather than the settings object directly, so the mock has
 * to publish it the way the patch component does.
 *
 * @param settingsLike - The settings the designation answers from.
 * @returns The patched method carrying the designation.
 */
function createGetAvailablePathForAttachments(settingsLike: SettingsLike): App['vault']['getAvailablePathForAttachments'] {
  const designation: Required<AttachmentUnitFolderDesignation> = {
    checkIsAttachmentUnitFolder: (folderPath) => settingsLike.isAttachmentUnitFolder(folderPath)
  };
  return castTo<App['vault']['getAvailablePathForAttachments']>(Object.assign(vi.fn(), designation));
}

let vaultRootFolder: TFolder;

function createCanvasReference(link: string): CanvasReference {
  return strictProxy<CanvasReference>({
    isCanvas: true,
    key: '',
    link,
    nodeIndex: 0,
    original: `![[${link}]]`,
    type: 'file'
  });
}

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
      isAttachmentUnitFolder: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      isExcludedFromMultipleNotesCheck: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      // The shipped default is `None`, so every pre-existing test runs with the orphan pass off.
      isOrphanAttachmentScanCandidate: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      isPathIgnored: vi.fn<(path: string) => boolean>().mockReturnValue(false)
    };
    attachmentFolder = strictProxy<TFolder>({ children: [], path: ATTACHMENT_FOLDER_PATH });
    getFolderByPath = vi.fn<(path: string) => null | TFolder>().mockReturnValue(attachmentFolder);
    app = strictProxy<App>({
      vault: strictProxy<App['vault']>({
        getAvailablePathForAttachments: createGetAvailablePathForAttachments(settings),
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
    const handedOverSettingsComponent = strictProxy<HandedOverSettingsComponent>({
      isPathIgnored: (path) => settings.isPathIgnored(path),
      settings: castTo<HandedOverSettings>(settings)
    });
    remover = new UnusedAttachmentsRemover({
      abortSignalComponent,
      app,
      attachmentPathManager,
      handedOverSettingsComponent,
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

  /*
   * Issue #72. A designated attachment unit folder is ONE attachment, so the sweep judges the folder
   * rather than its members: links from inside it do not keep it alive, and when nothing outside
   * references anything inside, the whole folder goes.
   */
  describe('attachment unit folders', () => {
    const UNIT_FOLDER_PATH = `${ATTACHMENT_FOLDER_PATH}/page_files`;

    let backlinksByPath: Map<string, string[]>;
    let drawing: TFile;
    let image: TFile;
    let note: TFile;
    let unitFolder: TFolder;
    let unitMembers: TFile[];

    beforeEach(() => {
      note = createFile('note.md');
      /*
       * A `.excalidraw.md` rather than a plain note on purpose: Obsidian indexes it, so it really does
       * produce backlinks, while `treatAsAttachmentExtensions` keeps `isNoteEx` false. That is exactly
       * the self-referencing unit the issue is about.
       */
      drawing = createFile(`${UNIT_FOLDER_PATH}/page.excalidraw.md`);
      image = createFile(`${UNIT_FOLDER_PATH}/img.png`);
      unitMembers = [drawing, image];
      unitFolder = createFolder(UNIT_FOLDER_PATH);

      mockIsFile.mockReturnValue(true);
      mockIsNote.mockImplementation((f) => f === note);
      mockIsFolder.mockReturnValue(false);
      mockIsCanvasFile.mockReturnValue(false);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([]);
      mockConfirm.mockResolvedValue(true);

      vi.mocked(settings.isAttachmentUnitFolder).mockImplementation((path) => path === UNIT_FOLDER_PATH);
      getFolderByPath.mockImplementation((path) => path === UNIT_FOLDER_PATH ? unitFolder : attachmentFolder);

      // The attachment folder's walk finds the members; the unit's walk re-reads them as one unit.
      vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        for (const member of unitMembers) {
          callback(member);
        }
      });

      backlinksByPath = new Map<string, string[]>();
      mockGetBacklinksForFileSafe.mockImplementation((params) => {
        const path = castTo<TFile>(params.pathOrFile).path;
        return Promise.resolve(createBacklinks(backlinksByPath.get(path) ?? []));
      });
    });

    it('should trash the whole unit folder when its members only reference each other', async () => {
      // The drawing embeds its sibling image. That is the unit describing itself, so it must not count.
      backlinksByPath.set(image.path, [drawing.path]);
      await runOperation([note]);
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, unitFolder);
    });

    it('should clean up the unit folder parent rather than the unit folder itself', async () => {
      backlinksByPath.set(image.path, [drawing.path]);
      await runOperation([note]);
      expect(mockCleanupEmptyFolders).toHaveBeenCalledExactlyOnceWith({
        app,
        emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
        folderPaths: [ATTACHMENT_FOLDER_PATH]
      });
    });

    it('should keep the unit whole when another note references any member', async () => {
      backlinksByPath.set(image.path, ['other.md']);
      await runOperation([note]);
      // The unreferenced drawing survives too: a unit that travels as one dies as one.
      expect(mockTrashSafe).not.toHaveBeenCalled();
      expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('No unused attachments found.');
    });

    it('should keep the unit whole when the scanning note itself references a member', async () => {
      /*
       * The deliberate asymmetry with the per-file rule, which filters the scanning note out. The note
       * sits OUTSIDE the unit, so its link in is a genuine outside reference.
       */
      backlinksByPath.set(image.path, [note.path]);
      await runOperation([note]);
      expect(mockTrashSafe).not.toHaveBeenCalled();
    });

    it('should keep the unit whole when a member is referenced from both inside and outside', async () => {
      // Guards against the inside-the-unit filter swallowing the outside hit alongside it.
      backlinksByPath.set(image.path, [drawing.path, 'other.md']);
      await runOperation([note]);
      expect(mockTrashSafe).not.toHaveBeenCalled();
    });

    it('should ignore an excluded note when deciding the unit is unreferenced', async () => {
      backlinksByPath.set(image.path, ['excluded.md']);
      vi.mocked(settings.isExcludedFromMultipleNotesCheck).mockImplementation((path) => path === 'excluded.md');
      await runOperation([note]);
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, unitFolder);
    });

    it('should fall back to the per-file rule when a real note lives inside the unit', async () => {
      /*
       * An attachment sweep never trashes a note on the user's behalf, so the whole folder comes off
       * the table and its members are judged one at a time again.
       */
      const scratch = createFile(`${UNIT_FOLDER_PATH}/scratch.md`);
      unitMembers = [drawing, image, scratch];
      vi.mocked(pluginSettingsComponent.isNoteEx).mockImplementation((f) => f === scratch);
      backlinksByPath.set(image.path, [drawing.path]);
      await runOperation([note]);
      // The folder survives; only the drawing, which nothing references at all, is trashed.
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, drawing);
    });

    it('should name the folder in the confirmation and say it goes whole', async () => {
      backlinksByPath.set(image.path, [drawing.path]);
      mockConfirm.mockResolvedValue(false);
      await runOperation([note]);

      const text = getConfirmMessageText();
      expect(text).toContain('1 attachment unit folder(s) will be moved to the trash with everything inside them.');
      expect(text).toContain(UNIT_FOLDER_PATH);
      // No individual-file section at all, so the dialog cannot read as "0 attachments".
      expect(text).not.toContain('attachment(s) will be moved to the trash.');
    });

    it('should trash a unit folder once when several notes reach it', async () => {
      // Every note whose attachment folder holds the unit reports it, so it has to be deduplicated
      // Before the trash loop: trashing the same folder twice throws on the second call.
      const otherNote = createFile('other-note.md');
      mockIsNote.mockImplementation((f) => f === note || f === otherNote);
      backlinksByPath.set(image.path, [drawing.path]);

      await runOperation([note, otherNote]);

      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, unitFolder);
    });

    it('should fall back to the per-file rule when the designated folder is not in the vault', async () => {
      /*
       * The designation is a published answer about a PATH, so it can outlive the folder it names —
       * a stale designated path, or a folder deleted between the walk and the judging. There is no
       * unit to judge then, and the members have to stay open to judgement rather than silently immortal.
       */
      getFolderByPath.mockImplementation((path) => path === UNIT_FOLDER_PATH ? null : attachmentFolder);
      backlinksByPath.set(image.path, [drawing.path]);

      await runOperation([note]);

      // Per-file again: the image keeps the drawing's link, and the drawing itself has none.
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, drawing);
    });

    it('should skip a folder inside the unit when reading its members', async () => {
      // The walk yields folders as well as files, and only the files are the unit's members.
      const subFolder = createFolder(`${UNIT_FOLDER_PATH}/sub`);
      unitMembers = [drawing, image, castTo<TFile>(subFolder)];
      mockIsFile.mockImplementation((abstractFile) => abstractFile !== subFolder);
      backlinksByPath.set(image.path, [drawing.path]);

      await runOperation([note]);

      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, unitFolder);
    });

    it('should trash several unit folders in path order, ahead of the loose attachments', async () => {
      const otherUnitFolderPath = `${ATTACHMENT_FOLDER_PATH}/other_files`;
      const otherUnitFolder = createFolder(otherUnitFolderPath);
      const otherImage = createFile(`${otherUnitFolderPath}/other.png`);
      const loose = createFile(`${ATTACHMENT_FOLDER_PATH}/loose.png`);
      const otherUnitMembers = [otherImage];

      vi.mocked(settings.isAttachmentUnitFolder).mockImplementation((path) => path === UNIT_FOLDER_PATH || path === otherUnitFolderPath);
      getFolderByPath.mockImplementation((path) => {
        switch (path) {
          case otherUnitFolderPath: {
            return otherUnitFolder;
          }
          case UNIT_FOLDER_PATH: {
            return unitFolder;
          }
          default: {
            return attachmentFolder;
          }
        }
      });

      // Each unit's walk sees only its own members; the attachment folder's walk sees everything.
      vi.spyOn(Vault, 'recurseChildren').mockImplementation((root, callback) => {
        let children: TFile[];
        if (root === unitFolder) {
          children = unitMembers;
        } else if (root === otherUnitFolder) {
          children = otherUnitMembers;
        } else {
          children = [...unitMembers, ...otherUnitMembers, loose];
        }
        for (const child of children) {
          callback(child);
        }
      });

      backlinksByPath.set(image.path, [drawing.path]);

      await runOperation([note]);

      /*
       * Folders first and in path order, then the attachment that belongs to no unit. The order is
       * the point: a folder takes everything inside it, so anything below it must not be trashed
       * again afterwards.
       */
      expect(mockTrashSafe.mock.calls.map((call) => castTo<TAbstractFile>(call[1]).path)).toStrictEqual([
        otherUnitFolderPath,
        UNIT_FOLDER_PATH,
        loose.path
      ]);
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

  /*
   * The attachment-driven pass (T847). Everything here goes through the VAULT-WIDE command, because that
   * is the only entry point that runs it — the per-note and per-folder scopes deliberately do not, since
   * "no note references this" is only trustworthy from a scan that read every note there is.
   */
  describe('attachments no note owns', () => {
    const ORPHAN_FOLDER_PATH = 'lost/assets';

    let noteFiles: TFile[];
    let orphan: TFile;
    let vaultFiles: TFile[];

    /**
     * Points the vault-root walk at {@link vaultFiles}, and every other walk at the files given.
     *
     * The remover recurses the root to build its scope and then recurses each attachment or unit folder it
     * resolves, so one mock has to answer both and tell them apart by which folder it was handed.
     *
     * @param otherFolderChildren - What a non-root walk yields.
     */
    function mockVaultWalk(otherFolderChildren: TFile[] = []): void {
      vi.spyOn(Vault, 'recurseChildren').mockImplementation((root, callback) => {
        for (const child of root === vaultRootFolder ? vaultFiles : otherFolderChildren) {
          callback(child);
        }
      });
    }

    async function runEntireVaultOperation(): Promise<void> {
      remover.deleteUnusedAttachmentsEntireVault();
      const params = castTo<QueueParamsLike>(mockAddToQueue.mock.calls[0]?.[0]);
      await params.operationFunction(new AbortController().signal);
    }

    beforeEach(() => {
      orphan = createFile(`${ORPHAN_FOLDER_PATH}/orphan.png`);
      vaultFiles = [orphan];
      // Nothing in these vaults is a note unless a test says so - that is the whole scenario.
      noteFiles = [];

      mockIsFile.mockImplementation((f) => f !== vaultRootFolder);
      mockIsFolder.mockImplementation((f) => f === vaultRootFolder);
      /*
       * Both predicates are driven off one list, because the sweep reads them against each other: the scope
       * walk gathers notes with `isNote` and rejects orphan candidates with `isNoteEx`. Letting them
       * disagree by accident makes a note its own attachment, which no real vault does.
       */
      mockIsNote.mockImplementation((f) => noteFiles.includes(castTo<TFile>(f)));
      vi.mocked(pluginSettingsComponent.isNoteEx).mockImplementation((f) => noteFiles.includes(castTo<TFile>(f)));
      mockIsCanvasFile.mockReturnValue(false);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([]);
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks([]));
      mockConfirm.mockResolvedValue(true);
      mockVaultWalk();
    });

    it('should not look at anything when the mode is off', async () => {
      await runEntireVaultOperation();
      expect(settings.isOrphanAttachmentScanCandidate).toHaveBeenCalledWith(orphan.path);
      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
      expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('No unused attachments found.');
    });

    it('should trash an attachment whose owning note is gone', async () => {
      vi.mocked(settings.isOrphanAttachmentScanCandidate).mockReturnValue(true);
      await runEntireVaultOperation();
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, orphan);
    });

    it('should confine the scan to the listed paths', async () => {
      const elsewhere = createFile('elsewhere/other.png');
      vaultFiles = [orphan, elsewhere];
      mockVaultWalk();
      vi.mocked(settings.isOrphanAttachmentScanCandidate).mockImplementation((path) => path.startsWith(`${ORPHAN_FOLDER_PATH}/`));

      await runEntireVaultOperation();

      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, orphan);
    });

    it('should skip an attachment whose own path is ignored', async () => {
      vi.mocked(settings.isOrphanAttachmentScanCandidate).mockReturnValue(true);
      vi.mocked(settings.isPathIgnored).mockImplementation((path) => path === orphan.path);

      await runEntireVaultOperation();

      expect(mockGetBacklinksForFileSafe).not.toHaveBeenCalled();
      expect(mockTrashSafe).not.toHaveBeenCalled();
      expect(warnSpy).toHaveBeenCalledWith(`Cannot delete unused attachment as its path is ignored: ${orphan.path}.`);
    });

    it('should keep an attachment a canvas embeds, which carries no backlink', async () => {
      /*
       * The regression this pass most needs. Obsidian does not index a canvas's embeds, so the file has no
       * backlink at all and a backlink lookup alone calls it unreferenced. Only the reference the canvas
       * scan reported keeps it alive.
       */
      const canvas = createFile('board.canvas');
      const embedded = createFile(`${ORPHAN_FOLDER_PATH}/embedded.png`);
      vaultFiles = [canvas, embedded];
      mockVaultWalk();
      noteFiles = [canvas];
      mockIsCanvasFile.mockImplementation((f) => f === canvas);
      mockGetCanvasReferences.mockResolvedValue([createCanvasReference(embedded.path)]);
      mockExtractLinkFile.mockReturnValue(embedded);
      vi.mocked(settings.isOrphanAttachmentScanCandidate).mockReturnValue(true);
      // The canvas owns no attachment folder of its own, so the note-driven pass contributes nothing.
      getFolderByPath.mockReturnValue(null);

      await runEntireVaultOperation();

      expect(mockTrashSafe).not.toHaveBeenCalled();
      expect(showNoticeSpy).toHaveBeenCalledExactlyOnceWith('No unused attachments found.');
    });

    it('should keep an attachment an ignored note still references', async () => {
      const ignoredNote = createFile('ignored/note.md');
      const referenced = createFile(`${ORPHAN_FOLDER_PATH}/referenced.png`);
      vaultFiles = [ignoredNote, referenced];
      mockVaultWalk();
      noteFiles = [ignoredNote];
      mockGetLinks.mockReturnValue([createReference(referenced.path)]);
      mockExtractLinkFile.mockReturnValue(referenced);
      vi.mocked(settings.isOrphanAttachmentScanCandidate).mockReturnValue(true);
      vi.mocked(settings.isPathIgnored).mockImplementation((path) => path === ignoredNote.path);

      await runEntireVaultOperation();

      expect(mockTrashSafe).not.toHaveBeenCalled();
    });

    it('should trash an unowned attachment unit folder whole', async () => {
      const unitFolderPath = `${ORPHAN_FOLDER_PATH}/page_files`;
      const member = createFile(`${unitFolderPath}/img.png`);
      const unitFolder = createFolder(unitFolderPath);
      vaultFiles = [member];
      mockVaultWalk([member]);
      getFolderByPath.mockImplementation((path) => path === unitFolderPath ? unitFolder : null);
      vi.mocked(settings.isAttachmentUnitFolder).mockImplementation((path) => path === unitFolderPath);
      vi.mocked(settings.isOrphanAttachmentScanCandidate).mockReturnValue(true);

      await runEntireVaultOperation();

      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, unitFolder);
    });

    it('should not judge an attachment the note-driven pass already listed', async () => {
      const note = createFile('note.md');
      const unused = createFile(`${ATTACHMENT_FOLDER_PATH}/unused.png`);
      vaultFiles = [note, unused];
      noteFiles = [note];
      mockVaultWalk([unused]);
      vi.mocked(settings.isOrphanAttachmentScanCandidate).mockReturnValue(true);

      await runEntireVaultOperation();

      // Judged once by the note that owns it, and not a second time by the pass for files nothing owns.
      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledExactlyOnceWith({
        app,
        pathOrFile: unused,
        timeoutInMilliseconds: 1000
      });
      expect(mockTrashSafe).toHaveBeenCalledExactlyOnceWith(app, unused);
    });
  });
});
