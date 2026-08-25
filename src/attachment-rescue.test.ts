import type {
  App,
  TFile
} from 'obsidian';
import type { CachedMetadataEx } from 'obsidian-dev-utils/obsidian/metadata-cache';
import type { Mock } from 'vitest';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';

import {
  AttachmentRescuer,
  pickRescueNotePath
} from './attachment-rescue.ts';
import { NO_PRIORITY_MATCH } from './note-priority.ts';
import { ActionContext } from './token-evaluator-context.ts';

interface SettingsLike {
  notePriorities: readonly string[];
  shouldRescueSharedAttachments: boolean;
}

const ATTACHMENT_PATH = 'assets/note-a/shared.png';

function createFile(path: string): TFile {
  return strictProxy<TFile>({
    extension: path.split('.').at(-1) ?? '',
    name: path.split('/').at(-1) ?? '',
    path,
    stat: strictProxy<TFile['stat']>({ ctime: 0, mtime: 0, size: 0 })
  });
}

describe('pickRescueNotePath', () => {
  it('should take the only surviving note without consulting the priority list', () => {
    // The list is empty by default, so ranking first would mean the rescue never fired for anybody
    // Who had not filled it in.
    const rank = vi.fn<(notePath: string) => number>();

    expect(pickRescueNotePath({
      entries: [],
      rank,
      survivingNotePaths: ['note-b.md']
    })).toBe('note-b.md');
    expect(rank).not.toHaveBeenCalled();
  });

  it('should leave several surviving notes alone while the priority list is empty', () => {
    expect(pickRescueNotePath({
      entries: [],
      rank: () => NO_PRIORITY_MATCH,
      survivingNotePaths: ['note-b.md', 'note-c.md']
    })).toBeNull();
  });

  it('should pick the highest-priority note among several', () => {
    expect(pickRescueNotePath({
      entries: ['.md', '.excalidraw.md'],
      rank: (notePath) => notePath === 'note-b.md' ? 0 : 1,
      survivingNotePaths: ['drawing.excalidraw.md', 'note-b.md']
    })).toBe('note-b.md');
  });

  it('should leave the attachment alone when the best rank is shared', () => {
    expect(pickRescueNotePath({
      entries: ['.md'],
      rank: () => 0,
      survivingNotePaths: ['note-b.md', 'note-c.md']
    })).toBeNull();
  });

  it('should leave the attachment alone when no note matches any entry', () => {
    expect(pickRescueNotePath({
      entries: ['.canvas'],
      rank: () => NO_PRIORITY_MATCH,
      survivingNotePaths: ['note-b.md', 'note-c.md']
    })).toBeNull();
  });

  it('should leave the attachment alone when nothing survives', () => {
    // The handler documents `survivingNotePaths` as never empty, so this is belt and braces.
    expect(pickRescueNotePath({
      entries: ['.md'],
      rank: () => 0,
      survivingNotePaths: []
    })).toBeNull();
  });
});

describe('AttachmentRescuer', () => {
  let app: App;
  let attachmentPathManager: AttachmentPathManager;
  let getAttachmentFolderFullPathForPath: Mock<AttachmentPathManager['getAttachmentFolderFullPathForPath']>;
  let getFileByPath: Mock<(path: string) => null | TFile>;
  let getFileCache: Mock<(file: TFile) => CachedMetadataEx | null>;
  let readBinary: Mock<(file: TFile) => Promise<ArrayBuffer>>;
  let rescuer: AttachmentRescuer;
  let settings: SettingsLike;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = {
      notePriorities: [],
      shouldRescueSharedAttachments: true
    };
    getFileByPath = vi.fn<(path: string) => null | TFile>().mockImplementation((path) => createFile(path));
    getFileCache = vi.fn<(file: TFile) => CachedMetadataEx | null>().mockReturnValue(null);
    readBinary = vi.fn<(file: TFile) => Promise<ArrayBuffer>>().mockResolvedValue(new ArrayBuffer(0));
    app = strictProxy<App>({
      metadataCache: strictProxy<App['metadataCache']>({
        getFileCache: (file: TFile) => getFileCache(file)
      }),
      vault: strictProxy<App['vault']>({
        getFileByPath: (path: string) => getFileByPath(path),
        readBinary: (file: TFile) => readBinary(file)
      })
    });
    getAttachmentFolderFullPathForPath = vi.fn<AttachmentPathManager['getAttachmentFolderFullPathForPath']>().mockResolvedValue('assets/note-b');
    attachmentPathManager = strictProxy<AttachmentPathManager>({
      getAttachmentFolderFullPathForPath: (params) => getAttachmentFolderFullPathForPath(params)
    });
    rescuer = new AttachmentRescuer({
      app,
      attachmentPathManager,
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
        settings: castTo<PluginSettings>(settings)
      })
    });
  });

  it('should keep the attachment where it is while the setting is off', async () => {
    settings.shouldRescueSharedAttachments = false;

    await expect(rescuer.getRescuePath({
      attachmentPath: ATTACHMENT_PATH,
      survivingNotePaths: ['note-b.md']
    })).resolves.toBeNull();
    expect(getAttachmentFolderFullPathForPath).not.toHaveBeenCalled();
  });

  it('should move the attachment into the surviving note attachment folder, keeping its name', async () => {
    await expect(rescuer.getRescuePath({
      attachmentPath: ATTACHMENT_PATH,
      survivingNotePaths: ['note-b.md']
    })).resolves.toBe('assets/note-b/shared.png');
    expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledWith(expect.objectContaining({
      actionContext: ActionContext.DeleteNote,
      attachmentFileName: 'shared.png',
      notePath: 'note-b.md'
    }));
  });

  it('should read the attachment content only when the folder pattern asks for it', async () => {
    // A bulk deletion walks past every attachment, so an eager binary read of each one is the
    // Bottleneck this lazy callback exists to avoid.
    await rescuer.getRescuePath({
      attachmentPath: ATTACHMENT_PATH,
      survivingNotePaths: ['note-b.md']
    });

    expect(readBinary).not.toHaveBeenCalled();

    const params = getAttachmentFolderFullPathForPath.mock.calls[0]?.[0];
    await params?.readAttachmentFileContent?.();

    expect(readBinary).toHaveBeenCalledWith(expect.objectContaining({ path: ATTACHMENT_PATH }));
  });

  it('should rank the surviving notes by the priority list', async () => {
    settings.notePriorities = ['.excalidraw.md', '.md'];

    await expect(rescuer.getRescuePath({
      attachmentPath: ATTACHMENT_PATH,
      survivingNotePaths: ['note-b.md', 'drawing.excalidraw.md']
    })).resolves.toBe('assets/note-b/shared.png');
    expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledWith(expect.objectContaining({ notePath: 'drawing.excalidraw.md' }));
  });

  it('should rank a surviving note by a frontmatter property', async () => {
    settings.notePriorities = ['property:excalidraw-plugin'];
    getFileCache.mockImplementation((file) =>
      file.path === 'drawing.excalidraw.md'
        ? castTo<CachedMetadataEx>({ frontmatter: { 'excalidraw-plugin': 'parsed' } })
        : null
    );

    await rescuer.getRescuePath({
      attachmentPath: ATTACHMENT_PATH,
      survivingNotePaths: ['note-b.md', 'drawing.excalidraw.md']
    });

    expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledWith(expect.objectContaining({ notePath: 'drawing.excalidraw.md' }));
  });

  it('should rank a surviving note that no longer resolves to a file', async () => {
    settings.notePriorities = ['.md'];
    getFileByPath.mockImplementation((path) => path === 'note-b.md' ? null : createFile(path));

    await expect(rescuer.getRescuePath({
      attachmentPath: ATTACHMENT_PATH,
      survivingNotePaths: ['note-b.md', 'drawing.canvas']
    })).resolves.toBe('assets/note-b/shared.png');
    expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledWith(expect.objectContaining({ notePath: 'note-b.md' }));
  });

  it('should keep the attachment where it is when the priority list settles nothing', async () => {
    settings.notePriorities = ['.md'];

    await expect(rescuer.getRescuePath({
      attachmentPath: ATTACHMENT_PATH,
      survivingNotePaths: ['note-b.md', 'note-c.md']
    })).resolves.toBeNull();
    expect(getAttachmentFolderFullPathForPath).not.toHaveBeenCalled();
  });

  it('should keep the attachment where it is when it cannot be resolved', async () => {
    getFileByPath.mockReturnValue(null);

    await expect(rescuer.getRescuePath({
      attachmentPath: ATTACHMENT_PATH,
      survivingNotePaths: ['note-b.md']
    })).resolves.toBeNull();
    expect(getAttachmentFolderFullPathForPath).not.toHaveBeenCalled();
  });
});
