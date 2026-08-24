import type {
  TAbstractFile,
  TFile,
  TFolder
} from 'obsidian';
import type { StrictProxyPartial } from 'obsidian-dev-utils/strict-proxy';
import type { MockInstance } from 'vitest';

import { ViewType } from '@obsidian-typings/obsidian-public-latest/implementations';
import { printError } from 'obsidian-dev-utils/error';
import { noopAsync } from 'obsidian-dev-utils/function';
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
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';
import type { TokenValidator } from './token-validator.ts';

import { ExternallyCreatedAttachmentHandlerComponent } from './externally-created-attachment-handler-component.ts';
import { selfWriteRegistry } from './self-write-registry.ts';

vi.mock('obsidian-dev-utils/error', () => ({
  printError: vi.fn<(error: unknown) => void>()
}));

interface GetAttachmentFolderFullPathForPathParams {
  readonly readAttachmentFileContent?: (() => Promise<ArrayBuffer>) | undefined;
}

interface SettingsOverrides {
  isPathIgnored?(path: string): boolean;
  shouldRenameAttachmentsCreatedByOtherPlugins?: boolean;
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

  function createSettings(overrides?: SettingsOverrides): PluginSettings {
    const partial: StrictProxyPartial<PluginSettings> = {
      isPathIgnored: overrides?.isPathIgnored ?? ((): boolean => false),
      shouldRenameAttachmentsCreatedByOtherPlugins: overrides?.shouldRenameAttachmentsCreatedByOtherPlugins ?? true
    };
    return strictProxy<PluginSettings>(partial);
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
      pluginSettingsComponent,
      tokenValidator: strictProxy<TokenValidator>({})
    });
    component.load();
  }

  /**
   * Writes a file the way a foreign plugin does — a path of its own, straight through
   * `createBinary` — WITHOUT firing the creation the handler reacts to.
   *
   * Writing and firing are separate steps because `obsidian-test-mocks` leaves `TFile.stat` at
   * all-zeroes (its vault never copies the adapter's stat onto the file), so a test has to stamp the
   * stat itself before the event — something the real Obsidian has already done by the time it fires
   * `create`.
   */
  async function writeForeignFile(path = FOREIGN_ATTACHMENT_PATH): Promise<TFile> {
    await getApp().vault.createFolder('wherever');
    await getApp().vault.createBinary(path, new ArrayBuffer(4));
    await flush();
    const file = getFile(path);
    file.stat.ctime = Date.now();
    return file;
  }

  async function fireCreate(abstractFile: TAbstractFile): Promise<void> {
    getApp().vault.trigger('create', abstractFile);
    await flush();
  }

  function getFile(path: string): TFile {
    const file = getApp().vault.getFileByPath(path);
    if (!file) {
      throw new Error(`No file at ${path}`);
    }

    return file;
  }

  function getFolder(path: string): TFolder {
    const folder = getApp().vault.getFolderByPath(path);
    if (!folder) {
      throw new Error(`No folder at ${path}`);
    }

    return folder;
  }

  async function createForeignAttachment(path = FOREIGN_ATTACHMENT_PATH): Promise<TFile> {
    const file = await writeForeignFile(path);
    await fireCreate(file);
    return file;
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
    await setUp({ settings: { shouldRenameAttachmentsCreatedByOtherPlugins: false } });

    await createForeignAttachment();

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore a file the plugin wrote itself', async () => {
    await setUp();
    const file = await writeForeignFile();

    selfWriteRegistry.register(file.path);
    await fireCreate(file);

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore a newly created note', async () => {
    await setUp();
    await getApp().vault.create('notes/another.md', '');
    const noteFile = getFile('notes/another.md');
    noteFile.stat.ctime = Date.now();

    await fireCreate(noteFile);

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore a folder', async () => {
    await setUp();
    await getApp().vault.createFolder('some-folder');

    await fireCreate(getFolder('some-folder'));

    expect(renameFileSpy).not.toHaveBeenCalled();
  });

  it('should ignore a file that already existed, such as one arriving from a sync', async () => {
    await setUp();
    const file = await writeForeignFile();
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
