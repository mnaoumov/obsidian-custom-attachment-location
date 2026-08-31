import type {
  App,
  TFile,
  WorkspaceLeaf
} from 'obsidian';
import type { ActiveFileProvider } from 'obsidian-dev-utils/obsidian/active-file-provider';
import type { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import type { Mock } from 'vitest';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { selectItem } from 'obsidian-dev-utils/obsidian/modals/select-item';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { NoteOwnerResolver } from '../note-owner-resolver.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { NoPriorityWinnerReason } from '../note-priority.ts';
import { GoToOwningNoteCommandHandler } from './go-to-owning-note-command-handler.ts';

interface ActiveFileProviderHolder {
  _activeFileProvider: ActiveFileProvider;
}

interface TestableHandler {
  canExecuteFile(file: TFile): boolean;
  executeFile(file: TFile): Promise<void>;
  icon: string;
  id: string;
  name: string;
  shouldAddToFileMenu(): boolean;
}

vi.mock('obsidian-dev-utils/obsidian/modals/select-item', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/modals/select-item')>(),
  selectItem: vi.fn()
}));

const mockSelectItem = vi.mocked(selectItem);

const ATTACHMENT_PATH = 'notes/attachments/img.png';

function createFile(path: string): TFile {
  return strictProxy<TFile>({
    extension: path.split('.').at(-1) ?? '',
    name: path.split('/').at(-1) ?? '',
    path
  });
}

function toTestable(handler: GoToOwningNoteCommandHandler): TestableHandler {
  return castTo<TestableHandler>(handler);
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('GoToOwningNoteCommandHandler', () => {
  let app: App;
  let findCandidateNotePaths: Mock<NoteOwnerResolver['findCandidateNotePaths']>;
  let findNoPriorityWinnerReason: Mock<NoteOwnerResolver['findNoPriorityWinnerReason']>;
  let getFileByPath: Mock<(path: string) => null | TFile>;
  let handler: GoToOwningNoteCommandHandler;
  let isNoteEx: Mock<() => boolean>;
  let openFile: Mock<(file: TFile) => Promise<void>>;
  let pickOwnerNotePath: Mock<NoteOwnerResolver['pickOwnerNotePath']>;
  let showNotice: Mock<PluginNoticeComponent['showNotice']>;

  beforeEach(() => {
    vi.clearAllMocks();
    openFile = vi.fn<(file: TFile) => Promise<void>>().mockResolvedValue();
    getFileByPath = vi.fn<(path: string) => null | TFile>().mockImplementation((path) => createFile(path));
    app = strictProxy<App>({
      vault: strictProxy<App['vault']>({
        getFileByPath: (path: string) => getFileByPath(path)
      }),
      workspace: strictProxy<App['workspace']>({
        getLeaf: () =>
          strictProxy<WorkspaceLeaf>({
            openFile: (file: TFile) => openFile(file)
          })
      })
    });
    findCandidateNotePaths = vi.fn<NoteOwnerResolver['findCandidateNotePaths']>().mockResolvedValue([]);
    pickOwnerNotePath = vi.fn<NoteOwnerResolver['pickOwnerNotePath']>().mockReturnValue(null);
    findNoPriorityWinnerReason = vi.fn<NoteOwnerResolver['findNoPriorityWinnerReason']>()
      .mockReturnValue(NoPriorityWinnerReason.EmptyList);
    showNotice = vi.fn<PluginNoticeComponent['showNotice']>();
    isNoteEx = vi.fn<() => boolean>().mockReturnValue(false);
    handler = new GoToOwningNoteCommandHandler({
      app,
      noteOwnerResolver: strictProxy<NoteOwnerResolver>({
        findCandidateNotePaths: (attachmentFile) => findCandidateNotePaths(attachmentFile),
        findNoPriorityWinnerReason: (notePaths) => findNoPriorityWinnerReason(notePaths),
        pickOwnerNotePath: (notePaths) => pickOwnerNotePath(notePaths)
      }),
      pluginNoticeComponent: strictProxy<PluginNoticeComponent>({
        showNotice: (message, options) => showNotice(message, options)
      }),
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
        isNoteEx: () => isNoteEx()
      })
    });
    castTo<ActiveFileProviderHolder>(handler)._activeFileProvider = strictProxy<ActiveFileProvider>({
      getActiveFile: () => createFile(ATTACHMENT_PATH)
    });
  });

  it('should construct with the correct command metadata', () => {
    expect(toTestable(handler).id).toBe('go-to-owning-note');
    expect(toTestable(handler).icon).toBe('file-symlink');
    expect(toTestable(handler).name).toBe('Go to owning note');
    expect(toTestable(handler).shouldAddToFileMenu()).toBe(true);
  });

  describe('canExecuteFile', () => {
    it('should accept an attachment', () => {
      expect(toTestable(handler).canExecuteFile(createFile(ATTACHMENT_PATH))).toBe(true);
    });

    it('should reject a note', () => {
      isNoteEx.mockReturnValue(true);
      expect(toTestable(handler).canExecuteFile(createFile('notes/note.md'))).toBe(false);
    });
  });

  describe('executeFile', () => {
    it('should report that nothing references the attachment', async () => {
      await toTestable(handler).executeFile(createFile(ATTACHMENT_PATH));
      expect(openFile).not.toHaveBeenCalled();
      expect(showNotice).toHaveBeenCalledExactlyOnceWith(expect.stringContaining(ATTACHMENT_PATH), undefined);
    });

    it('should open the only referencing note without consulting the priority list', async () => {
      findCandidateNotePaths.mockResolvedValue(['notes/note.md']);
      await toTestable(handler).executeFile(createFile(ATTACHMENT_PATH));
      expect(pickOwnerNotePath).not.toHaveBeenCalled();
      expect(mockSelectItem).not.toHaveBeenCalled();
      expect(openFile).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ path: 'notes/note.md' }));
    });

    it('should open the note the priority list names', async () => {
      findCandidateNotePaths.mockResolvedValue(['notes/a.md', 'notes/b.md']);
      pickOwnerNotePath.mockReturnValue('notes/b.md');
      await toTestable(handler).executeFile(createFile(ATTACHMENT_PATH));
      expect(mockSelectItem).not.toHaveBeenCalled();
      expect(openFile).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ path: 'notes/b.md' }));
    });

    it('should ask when the priority list names nobody, explaining why', async () => {
      findCandidateNotePaths.mockResolvedValue(['notes/a.md', 'notes/b.md']);
      findNoPriorityWinnerReason.mockReturnValue(NoPriorityWinnerReason.Tie);
      mockSelectItem.mockResolvedValue(castTo<never>('notes/a.md'));
      await toTestable(handler).executeFile(createFile(ATTACHMENT_PATH));
      const selectItemParams = mockSelectItem.mock.calls[0]?.[0];
      expect(mockSelectItem).toHaveBeenCalledOnce();
      expect(selectItemParams?.items).toEqual(['notes/a.md', 'notes/b.md']);
      expect(selectItemParams?.placeholder).toContain('match the Note priorities setting equally well');
      // `selectItem` is mocked, so it never renders; drive the row renderer directly.
      // Rows are shown as the bare note path.
      expect(selectItemParams?.itemTextFunction('notes/a.md')).toBe('notes/a.md');
      expect(openFile).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ path: 'notes/a.md' }));
    });

    it('should open nothing when the picker is dismissed', async () => {
      findCandidateNotePaths.mockResolvedValue(['notes/a.md', 'notes/b.md']);
      mockSelectItem.mockResolvedValue(null);
      await toTestable(handler).executeFile(createFile(ATTACHMENT_PATH));
      expect(openFile).not.toHaveBeenCalled();
    });

    it('should open nothing when the chosen note has since vanished', async () => {
      findCandidateNotePaths.mockResolvedValue(['notes/note.md']);
      getFileByPath.mockReturnValue(null);
      await toTestable(handler).executeFile(createFile(ATTACHMENT_PATH));
      expect(openFile).not.toHaveBeenCalled();
    });
  });
});
