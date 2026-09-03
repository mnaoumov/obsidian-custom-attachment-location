import type { CustomArrayDict } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  Reference,
  TFile,
  TFolder
} from 'obsidian';
import type { CachedMetadataEx } from 'obsidian-dev-utils/obsidian/metadata-cache';
import type { Mock } from 'vitest';

import { Vault } from 'obsidian';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { findAttachmentUnitFolderPath } from 'obsidian-dev-utils/obsidian/attachment-unit-folder';
import { isFile } from 'obsidian-dev-utils/obsidian/file-system';
import { getBacklinksForFileSafe } from 'obsidian-dev-utils/obsidian/metadata-cache';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';

import { NoteOwnerResolver } from './note-owner-resolver.ts';
import { NoPriorityWinnerReason } from './note-priority.ts';

interface SettingsLike {
  isAttachmentUnitFolder: Mock<(path: string) => boolean>;
  notePriorities: readonly string[];
}

vi.mock('obsidian-dev-utils/obsidian/attachment-unit-folder', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/attachment-unit-folder')>(),
  findAttachmentUnitFolderPath: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/file-system', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/file-system')>(),
  isFile: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/metadata-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/metadata-cache')>(),
  getBacklinksForFileSafe: vi.fn()
}));

const mockFindAttachmentUnitFolderPath = vi.mocked(findAttachmentUnitFolderPath);
const mockIsFile = vi.mocked(isFile);
const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);

function createBacklinks(keys: string[]): CustomArrayDict<Reference> {
  return strictProxy<CustomArrayDict<Reference>>({
    keys: () => keys
  });
}

function createFile(path: string): TFile {
  return strictProxy<TFile>({
    extension: path.split('.').at(-1) ?? '',
    name: path.split('/').at(-1) ?? '',
    path
  });
}

describe('NoteOwnerResolver', () => {
  let app: App;
  let getFileByPath: Mock<(path: string) => null | TFile>;
  let getFileCache: Mock<(file: TFile) => CachedMetadataEx | null>;
  let getFolderByPath: Mock<(path: string) => null | TFolder>;
  let isNoteEx: Mock<(path: string) => boolean>;
  let pluginSettingsComponent: PluginSettingsComponent;
  let resolver: NoteOwnerResolver;
  let settings: SettingsLike;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = {
      isAttachmentUnitFolder: vi.fn<(path: string) => boolean>().mockReturnValue(false),
      notePriorities: []
    };
    getFileByPath = vi.fn<(path: string) => null | TFile>().mockImplementation((path) => createFile(path));
    getFileCache = vi.fn<(file: TFile) => CachedMetadataEx | null>().mockReturnValue(null);
    getFolderByPath = vi.fn<(path: string) => null | TFolder>().mockReturnValue(null);
    app = strictProxy<App>({
      metadataCache: strictProxy<App['metadataCache']>({
        getFileCache: (file: TFile) => getFileCache(file)
      }),
      vault: strictProxy<App['vault']>({
        getFileByPath: (path: string) => getFileByPath(path),
        getFolderByPath: (path: string) => getFolderByPath(path)
      })
    });
    isNoteEx = vi.fn<(path: string) => boolean>().mockReturnValue(true);
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      isNoteEx: (pathOrFile) => isNoteEx(castTo<string>(pathOrFile)),
      settings: castTo<PluginSettings>(settings)
    });
    mockFindAttachmentUnitFolderPath.mockReturnValue(null);
    mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks([]));
    resolver = new NoteOwnerResolver({ app, pluginSettingsComponent });
  });

  describe('findCandidateNotePaths', () => {
    it('should return the attachment\'s own backlinks, sorted', async () => {
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['b.md', 'a.md']));
      await expect(resolver.findCandidateNotePaths(createFile('attachments/img.png'))).resolves.toEqual(['a.md', 'b.md']);
    });

    it('should return an empty list when nothing references the attachment', async () => {
      await expect(resolver.findCandidateNotePaths(createFile('attachments/img.png'))).resolves.toEqual([]);
    });

    it('should drop backlinks that are not notes', async () => {
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['note.md', 'board.canvas']));
      isNoteEx.mockImplementation((path) => path === 'note.md');
      await expect(resolver.findCandidateNotePaths(createFile('attachments/img.png'))).resolves.toEqual(['note.md']);
    });

    it('should not report the attachment as its own owner', async () => {
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks(['attachments/img.png', 'note.md']));
      await expect(resolver.findCandidateNotePaths(createFile('attachments/img.png'))).resolves.toEqual(['note.md']);
    });

    it('should consult the whole unit folder for an unlinked member', async () => {
      const attachmentFile = createFile('page_files/style.css');
      const entryPoint = createFile('page_files/page.html');
      mockFindAttachmentUnitFolderPath.mockReturnValue('page_files');
      getFolderByPath.mockReturnValue(strictProxy<TFolder>({ path: 'page_files' }));
      mockIsFile.mockReturnValue(true);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren').mockImplementation((_root, callback) => {
        callback(attachmentFile);
        callback(entryPoint);
      });
      mockGetBacklinksForFileSafe.mockImplementation((params) => Promise.resolve(createBacklinks(params.pathOrFile === 'page_files/page.html' ? ['note.md'] : [])));

      try {
        await expect(resolver.findCandidateNotePaths(attachmentFile)).resolves.toEqual(['note.md']);
      } finally {
        recurseSpy.mockRestore();
      }

      // The attachment itself is never asked about twice.
      expect(mockGetBacklinksForFileSafe).toHaveBeenCalledTimes(2);
    });

    it('should answer the unit-folder probe from the settings', async () => {
      // `findAttachmentUnitFolderPath` is mocked, so the real implementation never calls the predicate.
      // Drive it directly - it is the only thing binding the unit-folder probe to the settings.
      mockFindAttachmentUnitFolderPath.mockReturnValue(null);
      await resolver.findCandidateNotePaths(createFile('page_files/style.css'));

      const probeParams = mockFindAttachmentUnitFolderPath.mock.calls[0]?.[0];
      expect(probeParams?.attachmentPath).toBe('page_files/style.css');

      settings.isAttachmentUnitFolder.mockReturnValue(true);
      expect(probeParams?.checkIsAttachmentUnitFolder('page_files')).toBe(true);
      expect(settings.isAttachmentUnitFolder).toHaveBeenCalledExactlyOnceWith('page_files');
    });

    it('should ignore a unit folder that does not exist', async () => {
      mockFindAttachmentUnitFolderPath.mockReturnValue('page_files');
      getFolderByPath.mockReturnValue(null);
      const recurseSpy = vi.spyOn(Vault, 'recurseChildren');
      try {
        await expect(resolver.findCandidateNotePaths(createFile('page_files/style.css'))).resolves.toEqual([]);
      } finally {
        recurseSpy.mockRestore();
      }
      expect(recurseSpy).not.toHaveBeenCalled();
    });
  });

  describe('pickOwnerNotePath', () => {
    it('should return null when the priority list is empty', () => {
      expect(resolver.pickOwnerNotePath(['a.md', 'b.excalidraw.md'])).toBeNull();
    });

    it('should return the highest-priority note', () => {
      settings.notePriorities = ['.md', '.excalidraw.md'];
      expect(resolver.pickOwnerNotePath(['drawing.excalidraw.md', 'note.md'])).toBe('note.md');
    });

    it('should return null on a tie', () => {
      settings.notePriorities = ['.md'];
      expect(resolver.pickOwnerNotePath(['a.md', 'b.md'])).toBeNull();
    });
  });

  describe('filterTopRankNotePaths', () => {
    it('should keep every note when the priority list is empty', () => {
      expect(resolver.filterTopRankNotePaths(['a.md', 'b.excalidraw.md'])).toEqual(['a.md', 'b.excalidraw.md']);
    });

    it('should drop a note the list deliberately ranked lower', () => {
      // The reporter's case: the drawing also ends with `.md`, but the longer entry demotes it, so it
      // Has no say in the ambiguity and must not be offered as if it had.
      settings.notePriorities = ['.md', '.excalidraw.md'];
      expect(resolver.filterTopRankNotePaths(['a.md', 'b.md', 'drawing.excalidraw.md'])).toEqual(['a.md', 'b.md']);
    });

    it('should keep every note when none of them matches the list', () => {
      settings.notePriorities = ['.canvas'];
      expect(resolver.filterTopRankNotePaths(['a.md', 'b.md'])).toEqual(['a.md', 'b.md']);
    });

    it('should rank by frontmatter as pickOwnerNotePath does', () => {
      settings.notePriorities = ['property:pinned', '.md'];
      getFileCache.mockImplementation((file) => file.path === 'pinned.md' ? castTo<CachedMetadataEx>({ frontmatter: { pinned: true } }) : null);
      expect(resolver.filterTopRankNotePaths(['pinned.md', 'plain.md'])).toEqual(['pinned.md']);
    });

    it('should return the sole winner whenever pickOwnerNotePath names one', () => {
      settings.notePriorities = ['.md', '.excalidraw.md'];
      const notePaths = ['drawing.excalidraw.md', 'note.md'];
      expect(resolver.filterTopRankNotePaths(notePaths)).toEqual([resolver.pickOwnerNotePath(notePaths)]);
    });
  });

  describe('findNoPriorityWinnerReason', () => {
    it('should report an empty list', () => {
      expect(resolver.findNoPriorityWinnerReason(['a.md'])).toBe(NoPriorityWinnerReason.EmptyList);
    });

    it('should report that nothing matched', () => {
      settings.notePriorities = ['.canvas'];
      expect(resolver.findNoPriorityWinnerReason(['a.md', 'b.md'])).toBe(NoPriorityWinnerReason.NoMatch);
    });

    it('should report a tie', () => {
      settings.notePriorities = ['.md'];
      expect(resolver.findNoPriorityWinnerReason(['a.md', 'b.md'])).toBe(NoPriorityWinnerReason.Tie);
    });
  });

  describe('rankNote', () => {
    it('should rank by the most specific matching entry', () => {
      expect(resolver.rankNote(['.md', '.excalidraw.md'], 'drawing.excalidraw.md')).toBe(1);
    });

    it('should consult the note\'s frontmatter', () => {
      getFileCache.mockReturnValue(castTo<CachedMetadataEx>({ frontmatter: { pinned: true } }));
      expect(resolver.rankNote(['property:pinned'], 'note.md')).toBe(0);
    });

    it('should treat a missing note as having no frontmatter', () => {
      getFileByPath.mockReturnValue(null);
      expect(resolver.rankNote(['property:pinned'], 'note.md')).toBe(Infinity);
      expect(getFileCache).not.toHaveBeenCalled();
    });
  });
});
