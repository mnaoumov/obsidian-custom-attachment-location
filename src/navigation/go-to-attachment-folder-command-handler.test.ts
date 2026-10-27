import type { ActiveFileProvider } from '@mnaoumov/obsidian-lib/active-file-provider';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type {
  App,
  Notice,
  TAbstractFile,
  TFile,
  TFolder
} from 'obsidian';
import type { Mock } from 'vitest';

import { DUMMY_PATH } from '@mnaoumov/obsidian-lib/attachment-path';
import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { createFolderSafe } from '@mnaoumov/obsidian-lib/vault';
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
import { GoToAttachmentFolderCommandHandler } from './go-to-attachment-folder-command-handler.ts';

interface ActiveFileProviderHolder {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  _activeFileProvider: ActiveFileProvider;
}

interface SettingsLike {
  readonly isPathIgnored: Mock<(path: string) => boolean>;
}

interface TestableHandler {
  readonly canExecuteFile: (file: TFile) => boolean;
  readonly executeFile: (file: TFile) => Promise<void>;
  readonly icon: string;
  readonly id: string;
  readonly name: string;
  readonly shouldAddToFileMenu: () => boolean;
}

vi.mock('@mnaoumov/obsidian-lib/vault', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/vault')>(),
  createFolderSafe: vi.fn()
}));

const mockCreateFolderSafe = vi.mocked(createFolderSafe);

const ATTACHMENT_FOLDER_PATH = 'notes/attachments/note';

function createFile(path: string): TFile {
  return strictProxy<TFile>({
    extension: path.split('.').at(-1) ?? '',
    name: path.split('/').at(-1) ?? '',
    path
  });
}

function createFolder(path: string): TFolder {
  return strictProxy<TFolder>({ path });
}

function toTestable(handler: GoToAttachmentFolderCommandHandler): TestableHandler {
  return castTo<TestableHandler>(handler);
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('GoToAttachmentFolderCommandHandler', () => {
  let app: App;
  let attachmentPathManager: AttachmentPathManager;
  let getAttachmentFolderFullPathForPath: Mock<AttachmentPathManager['getAttachmentFolderFullPathForPath']>;
  let getEnabledPluginById: Mock<(id: string) => unknown>;
  let getFolderByPath: Mock<(path: string) => null | TFolder>;
  let handler: GoToAttachmentFolderCommandHandler;
  let hide: Mock<() => void>;
  let isNoteEx: Mock<() => boolean>;
  let pluginNoticeComponent: PluginNoticeComponent;
  let revealInFolder: Mock<(abstractFile: TAbstractFile) => void>;
  let settings: SettingsLike;
  let showNotice: Mock<PluginNoticeComponent['showNotice']>;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = { isPathIgnored: vi.fn<(path: string) => boolean>().mockReturnValue(false) };
    revealInFolder = vi.fn<(abstractFile: TAbstractFile) => void>();
    getEnabledPluginById = vi.fn<(id: string) => unknown>().mockReturnValue({ revealInFolder });
    getFolderByPath = vi.fn<(path: string) => null | TFolder>().mockReturnValue(null);
    app = strictProxy<App>({
      internalPlugins: strictProxy<App['internalPlugins']>({
        getEnabledPluginById: castTo<App['internalPlugins']['getEnabledPluginById']>((id: string) => getEnabledPluginById(id))
      }),
      vault: strictProxy<App['vault']>({
        getFolderByPath: (path: string) => getFolderByPath(path)
      })
    });
    getAttachmentFolderFullPathForPath = vi.fn<AttachmentPathManager['getAttachmentFolderFullPathForPath']>()
      .mockResolvedValue(ATTACHMENT_FOLDER_PATH);
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getAttachmentFolderFullPathForPath: (params) => getAttachmentFolderFullPathForPath(params)
    });
    hide = vi.fn<() => void>();
    showNotice = vi.fn<PluginNoticeComponent['showNotice']>().mockReturnValue(strictProxy<Notice>({ hide }));
    pluginNoticeComponent = strictProxy<PluginNoticeComponent>({
      showNotice: (message, options) => showNotice(message, options)
    });
    isNoteEx = vi.fn<() => boolean>().mockReturnValue(true);
    handler = new GoToAttachmentFolderCommandHandler({
      app,
      attachmentPathManager,
      handedOverSettingsComponent: strictProxy<HandedOverSettingsComponent>({
        isPathIgnored: (path) => settings.isPathIgnored(path)
      }),
      pluginNoticeComponent,
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
        isNoteEx: () => isNoteEx(),
        settings: castTo<PluginSettings>(settings)
      })
    });
    castTo<ActiveFileProviderHolder>(handler)._activeFileProvider = strictProxy<ActiveFileProvider>({
      getActiveFile: () => createFile('notes/note.md')
    });
  });

  it('should construct with the correct command metadata', () => {
    expect(toTestable(handler).id).toBe('go-to-attachment-folder');
    expect(toTestable(handler).icon).toBe('folder-open');
    expect(toTestable(handler).name).toBe('Go to attachment folder');
    expect(toTestable(handler).shouldAddToFileMenu()).toBe(true);
  });

  describe('canExecuteFile', () => {
    it('should accept a note', () => {
      expect(toTestable(handler).canExecuteFile(createFile('notes/note.md'))).toBe(true);
    });

    it('should reject an attachment', () => {
      isNoteEx.mockReturnValue(false);
      expect(toTestable(handler).canExecuteFile(createFile('notes/img.png'))).toBe(false);
    });

    it('should reject an ignored note', () => {
      settings.isPathIgnored.mockReturnValue(true);
      expect(toTestable(handler).canExecuteFile(createFile('notes/note.md'))).toBe(false);
    });
  });

  describe('executeFile', () => {
    it('should reveal the existing attachment folder', async () => {
      const attachmentFolder = createFolder(ATTACHMENT_FOLDER_PATH);
      getFolderByPath.mockReturnValue(attachmentFolder);
      await toTestable(handler).executeFile(createFile('notes/note.md'));
      expect(revealInFolder).toHaveBeenCalledExactlyOnceWith(attachmentFolder);
      expect(showNotice).not.toHaveBeenCalled();
    });

    it('should resolve the folder without letting the prompt token open a modal', async () => {
      getFolderByPath.mockReturnValue(createFolder(ATTACHMENT_FOLDER_PATH));
      await toTestable(handler).executeFile(createFile('notes/note.md'));
      expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
        attachmentFileName: DUMMY_PATH,
        notePath: 'notes/note.md'
      }));
    });

    it('should refuse to navigate when the folder varies per attachment', async () => {
      getAttachmentFolderFullPathForPath.mockResolvedValue(`notes/${DUMMY_PATH}`);
      await toTestable(handler).executeFile(createFile('notes/note.md'));
      expect(revealInFolder).not.toHaveBeenCalled();
      expect(getFolderByPath).not.toHaveBeenCalled();
      expect(showNotice).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('depends on the attachment being saved'), undefined);
    });

    it('should report a disabled file explorer', async () => {
      getFolderByPath.mockReturnValue(createFolder(ATTACHMENT_FOLDER_PATH));
      getEnabledPluginById.mockReturnValue(null);
      await toTestable(handler).executeFile(createFile('notes/note.md'));
      expect(revealInFolder).not.toHaveBeenCalled();
      expect(showNotice).toHaveBeenCalledExactlyOnceWith(expect.stringContaining('File explorer core plugin is disabled'), undefined);
    });

    describe('when the attachment folder does not exist', () => {
      let fragment: DocumentFragment;

      beforeEach(async () => {
        await toTestable(handler).executeFile(createFile('notes/note.md'));
        fragment = castTo<DocumentFragment>(showNotice.mock.calls[0]?.[0]);
      });

      it('should offer to create it instead of creating it', () => {
        expect(mockCreateFolderSafe).not.toHaveBeenCalled();
        expect(revealInFolder).not.toHaveBeenCalled();
        expect(showNotice).toHaveBeenCalledExactlyOnceWith(expect.any(DocumentFragment), { shouldHideOnClick: false });
        expect(fragment.textContent).toContain(ATTACHMENT_FOLDER_PATH);
      });

      it('should create and reveal the folder when the button is clicked', async () => {
        const createdFolder = createFolder(ATTACHMENT_FOLDER_PATH);
        getFolderByPath.mockReturnValue(createdFolder);
        fragment.querySelector('button')?.click();
        await vi.waitFor(() => {
          expect(revealInFolder).toHaveBeenCalledExactlyOnceWith(createdFolder);
        });
        expect(mockCreateFolderSafe).toHaveBeenCalledExactlyOnceWith(app, ATTACHMENT_FOLDER_PATH);
        expect(hide).toHaveBeenCalledOnce();
      });

      it('should reveal nothing when the folder is still absent after creating it', async () => {
        // The lookup after createFolderSafe is allowed to come back null.
        // Nothing guarantees a folder: the path may be occupied by a file, or the create refused.
        getFolderByPath.mockReturnValue(null);
        fragment.querySelector('button')?.click();
        await vi.waitFor(() => {
          expect(mockCreateFolderSafe).toHaveBeenCalledExactlyOnceWith(app, ATTACHMENT_FOLDER_PATH);
        });
        expect(revealInFolder).not.toHaveBeenCalled();
        expect(hide).toHaveBeenCalledOnce();
      });
    });
  });
});
