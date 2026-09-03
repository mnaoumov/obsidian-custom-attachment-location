import type {
  TAbstractFile,
  TFile
} from 'obsidian';
import type { MockInstance } from 'vitest';

import { ViewType } from '@obsidian-typings/obsidian-public-latest/implementations';
import { printError } from 'obsidian-dev-utils/error';
import { noopAsync } from 'obsidian-dev-utils/function';
import { dirname } from 'obsidian-dev-utils/path';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  App,
  Editor,
  MarkdownView
} from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { TokenValidator } from './token-validator.ts';

import { ExternallyCreatedAttachmentHandlerComponent } from './externally-created-attachment-handler-component.ts';
import { foreignWriteRegistry } from './foreign-write-registry.ts';
import {
  PluginSettings,
  RenameAttachmentsCreatedByOtherPluginsMode
} from './plugin-settings.ts';
import { selfWriteRegistry } from './self-write-registry.ts';

vi.mock('obsidian-dev-utils/error', () => ({
  printError: vi.fn<(error: unknown) => void>()
}));

interface ActiveTimeLike {
  activeTime: number;
}

interface FileViewLike {
  file: null | TFile;
}

interface GetAttachmentFolderFullPathForPathParams {
  readonly notePath?: string | undefined;
  readonly readAttachmentFileContent?: (() => Promise<ArrayBuffer>) | undefined;
}

interface SettingsOverrides {
  isPathIgnored?(path: string): boolean;
  otherPluginIdsForAttachmentRename?: string[];
  renameAttachmentsCreatedByOtherPluginsMode?: RenameAttachmentsCreatedByOtherPluginsMode;
}

interface SetupOverrides {
  generatedAttachmentFileBaseName?: string;
  isNoteEx?(pathOrFile: unknown): boolean;
  onGetAttachmentFolderFullPathForPath?(params: GetAttachmentFolderFullPathForPathParams): void;
  settings?: SettingsOverrides;
}

const NOTE_PATH = 'notes/my-note.md';
const FOREIGN_ATTACHMENT_PATH = 'wherever/mx-img-abc.png';
// Mirrors FRESHLY_CREATED_THRESHOLD_IN_MILLISECONDS in the component under test.
const FRESHLY_CREATED_THRESHOLD_IN_MILLISECONDS = 10_000;

const mockPrintError = vi.mocked(printError);

describe('ExternallyCreatedAttachmentHandlerComponent', () => {
  let app: App;
  let component: ExternallyCreatedAttachmentHandlerComponent;
  let renameFileSpy: MockInstance<(file: TAbstractFile, newPath: string) => Promise<void>>;

  beforeEach(() => {
    app = App.createConfigured__();
    mockPrintError.mockClear();
  });

  afterEach(() => {
    component.unload();
    vi.restoreAllMocks();
  });

  function getApp(): ReturnType<App['asOriginalType__']> {
    return app.asOriginalType__();
  }

  function getPath(pathOrFile: unknown): string {
    return typeof pathOrFile === 'string' ? pathOrFile : (pathOrFile as TAbstractFile).path;
  }

  /*
   * A REAL `PluginSettings` rather than a proxy: the component now delegates the include / exclude decision
   * to `shouldRenameAttachmentCreatedByPlugin`, and stubbing that would test the stub instead of the rule.
   */
  function createSettings(overrides?: SettingsOverrides): PluginSettings {
    const settings = new PluginSettings();
    settings.renameAttachmentsCreatedByOtherPluginsMode = overrides?.renameAttachmentsCreatedByOtherPluginsMode
      ?? RenameAttachmentsCreatedByOtherPluginsMode.All;
    settings.otherPluginIdsForAttachmentRename = overrides?.otherPluginIdsForAttachmentRename ?? [];
    return settings;
  }

  async function setUp(overrides?: SetupOverrides): Promise<void> {
    const attachmentPathManager = strictProxy<AttachmentPathManager>({
      getAttachmentFolderFullPathForPath: (params: GetAttachmentFolderFullPathForPathParams): Promise<string> => {
        overrides?.onGetAttachmentFolderFullPathForPath?.(params);
        return Promise.resolve('notes/assets');
      },
      getGeneratedAttachmentFileBaseName: (): Promise<string> => Promise.resolve(overrides?.generatedAttachmentFileBaseName ?? 'renamed')
    });

    const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      // A note is anything ending in `.md`, which is all that matters to the gates under test.
      isNoteEx: overrides?.isNoteEx ?? ((pathOrFile: unknown): boolean => getPath(pathOrFile).endsWith('.md')),
      settings: createSettings(overrides?.settings)
    });

    await getApp().vault.createFolder('notes');
    await getApp().vault.create(NOTE_PATH, '');
    vi.spyOn(getApp().workspace, 'getActiveFile').mockReturnValue(getApp().vault.getFileByPath(NOTE_PATH));

    renameFileSpy = vi.spyOn(getApp().fileManager, 'renameFile');

    component = new ExternallyCreatedAttachmentHandlerComponent({
      app: getApp(),
      attachmentPathManager,
      handedOverSettingsComponent: strictProxy<HandedOverSettingsComponent>({
        isPathIgnored: overrides?.settings?.isPathIgnored ?? ((): boolean => false)
      }),
      pluginSettingsComponent,
      tokenValidator: strictProxy<TokenValidator>({})
    });
    component.load();
  }

  /**
   * Creates a file the way a foreign plugin does — a path of its own, straight through
   * `createBinary`.
   *
   * That single call is the whole simulation: `obsidian-test-mocks` stats the new file from the
   * adapter and fires `create` for it, exactly as the real vault does, so nothing here stamps a
   * `ctime` or fires the event by hand.
   */
  async function createForeignAttachment(path = FOREIGN_ATTACHMENT_PATH): Promise<TFile> {
    const parentFolderPath = dirname(path);
    if (!await getApp().vault.exists(parentFolderPath)) {
      await getApp().vault.createFolder(parentFolderPath);
    }

    const file = await getApp().vault.createBinary(path, new ArrayBuffer(4));
    await flush();
    return file;
  }

  async function fireCreate(abstractFile: TAbstractFile): Promise<void> {
    getApp().vault.trigger('create', abstractFile);
    await flush();
  }

  async function flush(): Promise<void> {
    for (let index = 0; index < 20; index++) {
      await noopAsync();
    }
  }

  it('should move and rename an attachment another plugin created', async () => {
    await setUp();

    await createForeignAttachment();

    expect(renameFileSpy).toHaveBeenCalledOnce();
    expect(renameFileSpy.mock.calls[0]?.[1]).toBe('notes/assets/renamed.png');
  });

  it('should create the destination folder the template resolves to', async () => {
    await setUp();
    expect(await getApp().vault.exists('notes/assets')).toBe(false);

    await createForeignAttachment();

    expect(await getApp().vault.exists('notes/assets')).toBe(true);
  });

  it('should offer the attachment content lazily, so content-based tokens can resolve', async () => {
    let readContent: (() => Promise<ArrayBuffer>) | undefined;
    await setUp({
      onGetAttachmentFolderFullPathForPath: (params): void => {
        readContent = params.readAttachmentFileContent;
      }
    });

    await createForeignAttachment();

    expect(readContent).toBeTypeOf('function');
    // The bytes are read on demand only; a template that never asks for them never pays for the read.
    const content = await readContent?.();
    expect(content?.byteLength).toBe(4);
  });

  it('should reuse the destination folder when it already exists', async () => {
    await setUp();
    await getApp().vault.createFolder('notes/assets');
    const createFolderSpy = vi.spyOn(getApp().vault, 'createFolder');

    await createForeignAttachment();

    expect(createFolderSpy).not.toHaveBeenCalledWith('notes/assets');
    expect(renameFileSpy).toHaveBeenCalledOnce();
  });

  it('should do nothing when the setting is off', async () => {
    await setUp({ settings: { renameAttachmentsCreatedByOtherPluginsMode: RenameAttachmentsCreatedByOtherPluginsMode.None } });

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should rename an attachment created by a listed plugin', async () => {
    await setUp({
      settings: {
        otherPluginIdsForAttachmentRename: ['media-extended'],
        renameAttachmentsCreatedByOtherPluginsMode: RenameAttachmentsCreatedByOtherPluginsMode.OnlyListedPlugins
      }
    });
    foreignWriteRegistry.register(FOREIGN_ATTACHMENT_PATH, 'media-extended');

    await createForeignAttachment();

    expect(renameFileSpy).toHaveBeenCalledOnce();
  });

  it('should leave an attachment created by an unlisted plugin alone', async () => {
    await setUp({
      settings: {
        otherPluginIdsForAttachmentRename: ['media-extended'],
        renameAttachmentsCreatedByOtherPluginsMode: RenameAttachmentsCreatedByOtherPluginsMode.OnlyListedPlugins
      }
    });
    foreignWriteRegistry.register(FOREIGN_ATTACHMENT_PATH, 'excalidraw');

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should leave an attachment it cannot attribute alone when only listed plugins are renamed', async () => {
    await setUp({
      settings: {
        otherPluginIdsForAttachmentRename: ['media-extended'],
        renameAttachmentsCreatedByOtherPluginsMode: RenameAttachmentsCreatedByOtherPluginsMode.OnlyListedPlugins
      }
    });

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should skip an excluded plugin and rename everything else, attributable or not', async () => {
    await setUp({
      settings: {
        otherPluginIdsForAttachmentRename: ['media-extended'],
        renameAttachmentsCreatedByOtherPluginsMode: RenameAttachmentsCreatedByOtherPluginsMode.AllExceptListedPlugins
      }
    });
    foreignWriteRegistry.register(FOREIGN_ATTACHMENT_PATH, 'media-extended');

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should rename an attachment it cannot attribute when all but the listed plugins are renamed', async () => {
    await setUp({
      settings: {
        otherPluginIdsForAttachmentRename: ['media-extended'],
        renameAttachmentsCreatedByOtherPluginsMode: RenameAttachmentsCreatedByOtherPluginsMode.AllExceptListedPlugins
      }
    });

    await createForeignAttachment();

    expect(renameFileSpy).toHaveBeenCalledOnce();
  });

  it('should ignore a file the plugin wrote itself', async () => {
    await setUp();
    // The plugin claims the path BEFORE writing it, which is the order the component documents.
    selfWriteRegistry.register(FOREIGN_ATTACHMENT_PATH);

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore a newly created note', async () => {
    await setUp();

    await getApp().vault.create('notes/another.md', '');
    await flush();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore a folder', async () => {
    await setUp();

    await getApp().vault.createFolder('some-folder');
    await flush();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore a file that already existed, such as one arriving from a sync', async () => {
    /*
     * Written before the component is listening, so its own `create` goes unheard — then `create`
     * replays for it, the way a sync catching up or a folder import replays one for a file that
     * already existed.
     */
    await getApp().vault.createFolder('wherever');
    const file = await getApp().vault.createBinary(FOREIGN_ATTACHMENT_PATH, new ArrayBuffer(4));
    await setUp();
    // Backdated past the window, the way a synced or imported file looks when `create` replays.
    file.stat.ctime = Date.now() - FRESHLY_CREATED_THRESHOLD_IN_MILLISECONDS - 1;

    await fireCreate(file);

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore an attachment on an ignored path', async () => {
    await setUp({ settings: { isPathIgnored: (path: string): boolean => path === FOREIGN_ATTACHMENT_PATH } });

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore an attachment created while the active note is on an ignored path', async () => {
    await setUp({ settings: { isPathIgnored: (path: string): boolean => path === NOTE_PATH } });

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should do nothing when there is no active note to resolve the templates against', async () => {
    await setUp();
    vi.spyOn(getApp().workspace, 'getActiveFile').mockReturnValue(null);

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should do nothing when the active file is not a note', async () => {
    await setUp({ isNoteEx: (): boolean => false });

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should leave an attachment already at its proper path alone', async () => {
    await setUp({ generatedAttachmentFileBaseName: 'already-right' });
    await getApp().vault.createFolder('notes/assets');

    await createForeignAttachment('notes/assets/already-right.png');

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  /**
   * Opens a markdown leaf holding `content`, standing in for the note a foreign plugin has just
   * inserted its embed into but whose editor has not saved yet.
   */
  async function openEditorWith(content: string): Promise<Editor> {
    const leaf = app.workspace.getLeaf(true);
    const view = MarkdownView.create2__(leaf);
    await leaf.open(view.asOriginalType7__());
    await leaf.setViewState({ type: ViewType.Markdown });
    view.editor.setValue(content);
    return view.editor;
  }

  /**
   * Opens the note in a markdown leaf, so the leaf carries a `file` the handler can fall back to when
   * the ACTIVE file is not a note at all.
   */
  async function openNoteLeaf(notePath = NOTE_PATH, activeTime?: number): Promise<void> {
    await openEditorWith('');
    const leaf = getApp().workspace.getLeavesOfType(ViewType.Markdown).at(-1);
    // `obsidian-test-mocks` puts neither a file nor an `activeTime` on a leaf, so stand both up.
    const view: unknown = leaf?.view;
    (view as FileViewLike).file = getApp().vault.getFileByPath(notePath);
    if (activeTime !== undefined) {
      const leafValue: unknown = leaf;
      (leafValue as ActiveTimeLike).activeTime = activeTime;
    }
  }

  it('should repoint a link the creating plugin left unsaved in an editor', async () => {
    await setUp();
    /*
     * The rename only rewrites references the metadata cache knows about, and an embed inserted into
     * an unsaved editor is not one of them — without the editor pass the note keeps pointing at a
     * path that no longer exists.
     */
    const editor = await openEditorWith(`intro\n![[${FOREIGN_ATTACHMENT_PATH}]]\noutro`);

    await createForeignAttachment();

    expect(editor.getValue()).toBe('intro\n![[notes/assets/renamed.png]]\noutro');
  });

  it('should repoint a shortest-form wikilink, the spelling Obsidian actually inserts', async () => {
    await setUp();
    /*
     * Media Extended inserts `![[<file name>|<alias>]]` — no folder at all, because shortest-form links
     * are Obsidian's default. Repointing only the full-path spelling left that embed dangling; caught
     * by driving the real plugin, so it is asserted here.
     */
    const editor = await openEditorWith('![[mx-img-abc.png|Some title]]');

    await createForeignAttachment();

    expect(editor.getValue()).toBe('![[renamed.png|Some title]]');
  });

  it('should resolve the note from the most recent markdown leaf when the active file is not a note', async () => {
    /*
     * The creating plugin need not be driven from a note: Media Extended's screenshot command runs in
     * its own player leaf, so the active file is the VIDEO. Taking that at face value abandoned every
     * screenshot taken the way issue #59's reporter takes them.
     *
     * The video is written before the component is listening, so it is a player's media rather than
     * another foreign creation to react to.
     */
    const videoFile = await getApp().vault.createBinary('some-video.mp4', new ArrayBuffer(4));
    await setUp();
    await openNoteLeaf();
    vi.spyOn(getApp().workspace, 'getActiveFile').mockReturnValue(videoFile);

    await createForeignAttachment();

    expect(renameFileSpy).toHaveBeenCalledOnce();
    expect(renameFileSpy.mock.calls[0]?.[1]).toBe('notes/assets/renamed.png');
  });

  it('should pick the MOST recently active markdown leaf, not merely the first open one', async () => {
    let chosenNotePath: string | undefined;
    await setUp({
      onGetAttachmentFolderFullPathForPath: (params): void => {
        chosenNotePath = params.notePath;
      }
    });
    await getApp().vault.create('notes/stale.md', '');
    await getApp().vault.create('notes/newest.md', '');
    await getApp().vault.create('notes/middling.md', '');
    await openNoteLeaf('notes/stale.md', 1);
    await openNoteLeaf('notes/newest.md', 9);
    await openNoteLeaf('notes/middling.md', 5);
    vi.spyOn(getApp().workspace, 'getActiveFile').mockReturnValue(null);

    await createForeignAttachment();

    expect(chosenNotePath).toBe('notes/newest.md');
  });

  it('should repoint a percent-encoded Markdown link too', async () => {
    await setUp();
    const editor = await openEditorWith(`![](${encodeURI(FOREIGN_ATTACHMENT_PATH)})`);

    await createForeignAttachment();

    expect(editor.getValue()).toBe('![](notes/assets/renamed.png)');
  });

  it('should leave an editor that does not mention the attachment untouched', async () => {
    await setUp();
    const editor = await openEditorWith('nothing to do with it');
    const transactionSpy = vi.spyOn(editor, 'transaction');

    await createForeignAttachment();

    expect(transactionSpy).not.toHaveBeenCalled();
    expect(editor.getValue()).toBe('nothing to do with it');
  });

  it('should report a failed move instead of swallowing it', async () => {
    await setUp();
    renameFileSpy.mockRejectedValue(new Error('boom'));

    await createForeignAttachment();

    expect(mockPrintError).toHaveBeenCalledOnce();
  });
});
