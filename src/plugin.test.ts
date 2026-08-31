/* eslint-disable perfectionist/sort-named-imports -- dprint orders these members by their ORIGINAL name (`Plugin` before `PluginManifest`) while perfectionist orders them by the LOCAL alias (`PluginManifest` before `PluginOriginal`). For an aliased import the two orders conflict, and satisfying one re-breaks the other. */
import type {
  App as AppOriginal,
  Plugin as PluginOriginal,
  PluginManifest,
  TFile
} from 'obsidian';
/* eslint-enable perfectionist/sort-named-imports -- Only the aliased import above is exempt. */
import type { DisposableEx } from 'obsidian-dev-utils/disposable';
import type { CommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/command-handler';
import type { NotebookNavigatorMenuDispose } from 'obsidian-dev-utils/obsidian/notebook-navigator';
import type { Mock } from 'vitest';

import { Component } from 'obsidian';
import {
  noop,
  noopAsync
} from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { CommandHandlerComponent } from 'obsidian-dev-utils/obsidian/command-handlers/command-handler-component';
import { OpenDemoVaultCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/open-demo-vault-command-handler';
import { PluginSettingsTabComponent } from 'obsidian-dev-utils/obsidian/components/plugin-settings-tab-component';
import { RenameDeleteHandlerComponent } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import { NOTEBOOK_NAVIGATOR_PLUGIN_ID } from 'obsidian-dev-utils/obsidian/notebook-navigator';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { ArrayBufferMap } from './array-buffer-map.ts';
import { AttachmentCollector } from './attachment-collector.ts';
import { AttachmentPathManager } from './attachment-path-manager.ts';
import { AttachmentRescuer } from './attachment-rescue.ts';
import { AttachmentSaver } from './attachment-saver.ts';
import { CollectAttachmentsEntireVaultCommandHandler } from './command-handlers/collect-attachments-entire-vault-command-handler.ts';
import { CollectAttachmentsInCurrentFolderCommandHandler } from './command-handlers/collect-attachments-in-current-folder-command-handler.ts';
import { CollectAttachmentsInFileCommandHandler } from './command-handlers/collect-attachments-in-file-command-handler.ts';
import { DeleteUnusedAttachmentsEntireVaultCommandHandler } from './command-handlers/delete-unused-attachments-entire-vault-command-handler.ts';
import { DeleteUnusedAttachmentsInFileCommandHandler } from './command-handlers/delete-unused-attachments-in-file-command-handler.ts';
import { GoToAttachmentFolderCommandHandler } from './command-handlers/go-to-attachment-folder-command-handler.ts';
import { GoToOwningNoteCommandHandler } from './command-handlers/go-to-owning-note-command-handler.ts';
import { MoveAttachmentToProperFolderCommandHandler } from './command-handlers/move-attachment-to-proper-folder-command-handler.ts';
import { CustomAttachmentLocationComponent } from './custom-attachment-location-component.ts';
import { ImageManager } from './image-manager.ts';
import { ImageSizeMap } from './image-size-map.ts';
import { MarkdownUrlMap } from './markdown-url-map.ts';
import { AppSaveAttachmentPatchComponent } from './patches/app-save-attachment-patch-component.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import { PluginSettingsTab } from './plugin-settings-tab.ts';
import { TokenValidator } from './token-validator.ts';
import { TokenizedStringLanguageComponent } from './tokenized-string-language-component.ts';
import { UnusedAttachmentsRemover } from './unused-attachments-remover.ts';

// --- Hoisted shared state ---

const hoisted = vi.hoisted(() => ({
  getRescuePath: vi.fn((_params: unknown): Promise<null | string> => Promise.resolve('assets/note-b/shared.png')),
  isNoteEx: vi.fn((_path: string): boolean => true),
  isPathIgnored: vi.fn((_path: string): boolean => false),
  settings: {
    emptyFolderBehavior: 'Keep',
    isPathIgnored: (path: string): boolean => hoisted.isPathIgnored(path),
    shouldDeleteOrphanAttachments: true,
    shouldHandleRenames: true,
    shouldRenameAttachmentFiles: false,
    shouldRenameAttachmentFolder: false
  }
}));

// --- Collaborator dev-utils components added as children: stub as constructor spies returning a real Component so the real addChild lifecycle can load them while capturing constructor args. ---

vi.mock('obsidian-dev-utils/obsidian/components/plugin-settings-tab-component', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  PluginSettingsTabComponent: vi.fn(function pluginSettingsTabComponentStub() {
    return new Component();
  })
}));

vi.mock('obsidian-dev-utils/obsidian/components/rename-delete-handler-component', async (importOriginal) => {
  const original = await importOriginal<typeof import('obsidian-dev-utils/obsidian/components/rename-delete-handler-component')>();
  return {
    ...original,
    // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
    RenameDeleteHandlerComponent: vi.fn(function renameDeleteHandlerComponentStub() {
      return new Component();
    })
  };
});

// --- Collaborator dev-utils components NOT added as children: bare constructor spies. ---

// `PluginDataHandler` and `PluginEventSourceImpl` are NOT stubbed: since obsidian-dev-utils 93.2 the base
// Builds its own settings component out of them during `onload`, and that component really calls
// `pluginEventSource.on`, so a bare `vi.fn()` double makes the base throw before `onloadImpl` runs (G49).
// --- The plugin's OWN sibling modules: collaborators added as children return a real Component; the rest are bare constructor spies. ---

vi.mock('./array-buffer-map.ts', () => ({
  ArrayBufferMap: vi.fn()
}));

vi.mock('./attachment-collector.ts', () => ({
  AttachmentCollector: vi.fn()
}));

vi.mock('./attachment-path-manager.ts', () => ({
  AttachmentPathManager: vi.fn()
}));

vi.mock('./attachment-rescue.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works.
  AttachmentRescuer: vi.fn(function attachmentRescuerStub() {
    return {
      getRescuePath: (params: unknown): Promise<null | string> => hoisted.getRescuePath(params)
    };
  })
}));

vi.mock('./attachment-saver.ts', () => ({
  AttachmentSaver: vi.fn()
}));

vi.mock('./command-handlers/collect-attachments-entire-vault-command-handler.ts', () => ({
  CollectAttachmentsEntireVaultCommandHandler: vi.fn()
}));

vi.mock('./command-handlers/collect-attachments-in-current-folder-command-handler.ts', () => ({
  CollectAttachmentsInCurrentFolderCommandHandler: vi.fn()
}));

vi.mock('./command-handlers/collect-attachments-in-file-command-handler.ts', () => ({
  CollectAttachmentsInFileCommandHandler: vi.fn()
}));

vi.mock('./command-handlers/delete-unused-attachments-in-file-command-handler.ts', () => ({
  DeleteUnusedAttachmentsInFileCommandHandler: vi.fn()
}));

vi.mock('./command-handlers/go-to-attachment-folder-command-handler.ts', () => ({
  GoToAttachmentFolderCommandHandler: vi.fn()
}));

vi.mock('./command-handlers/go-to-owning-note-command-handler.ts', () => ({
  GoToOwningNoteCommandHandler: vi.fn()
}));

vi.mock('./command-handlers/move-attachment-to-proper-folder-command-handler.ts', () => ({
  MoveAttachmentToProperFolderCommandHandler: vi.fn()
}));

vi.mock('./custom-attachment-location-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  CustomAttachmentLocationComponent: vi.fn(function customAttachmentLocationComponentStub() {
    return new Component();
  })
}));

vi.mock('./image-manager.ts', () => ({
  ImageManager: vi.fn()
}));

vi.mock('./image-size-map.ts', () => ({
  ImageSizeMap: vi.fn()
}));

vi.mock('./markdown-url-map.ts', () => ({
  MarkdownUrlMap: vi.fn()
}));

vi.mock('./patches/app-save-attachment-patch-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  AppSaveAttachmentPatchComponent: vi.fn(function appSaveAttachmentPatchComponentStub() {
    return new Component();
  })
}));

vi.mock('./plugin-settings-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component carrying the stubbed settings.
  PluginSettingsComponent: vi.fn(function pluginSettingsComponentStub() {
    const component = new Component();
    Object.assign(component, {
      isNoteEx: (path: string): boolean => hoisted.isNoteEx(path),
      settings: hoisted.settings
    });
    return component;
  })
}));

vi.mock('./plugin-settings-tab.ts', () => ({
  PluginSettingsTab: vi.fn()
}));

vi.mock('./tokenized-string-language-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  TokenizedStringLanguageComponent: vi.fn(function tokenizedStringLanguageComponentStub() {
    return new Component();
  })
}));

vi.mock('./token-validator.ts', () => ({
  TokenValidator: vi.fn()
}));

vi.mock('./unused-attachments-remover.ts', () => ({
  UnusedAttachmentsRemover: vi.fn()
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede the import of the module under test.
import { Plugin } from './plugin.ts';

// The base pre-wires `commandHandlerComponent`; stub its `registerCommandHandlers` so the plugin's registration is asserted without exercising the mocked command handlers.
vi.spyOn(CommandHandlerComponent.prototype, 'registerCommandHandlers').mockResolvedValue(castTo<DisposableEx>({}));

interface AppGlobal {
  app: AppOriginal;
}

interface CustomAttachmentLocationParamsProbe {
  pluginDirectory: string;
}

interface RenameDeleteHandlerParamsProbe {
  settingsBuilder(): SettingsBuilderProbe;
}

interface SettingsBuilderProbe {
  emptyFolderBehavior: string;
  getRescuePath(params: unknown): Promise<null | string>;
  isNote(path: string): boolean;
  isPathIgnored(path: string): boolean;
  shouldUpdateFileNameAliases: boolean;
}

const STRICT_PROXY_TARGET_SYMBOL = Symbol.for('strictProxyTarget');

const manifest = castTo<PluginManifest>({
  author: 'test',
  description: 'test',
  // eslint-disable-next-line unicorn/name-replacements -- `dir` is an Obsidian `PluginManifest` member name.
  dir: 'plugins/custom-attachment-location',
  id: 'custom-attachment-location',
  minAppVersion: '1.0.0',
  name: 'Custom Attachment Location',
  version: '10.0.0'
});

let app: AppOriginal;
let getPluginMock: Mock<(pluginId: string) => null | PluginOriginal>;

beforeEach(() => {
  vi.clearAllMocks();
  hoisted.isNoteEx.mockReturnValue(true);
  hoisted.isPathIgnored.mockReturnValue(false);
  const appMock = App.createConfigured__();
  appMock.workspace.onLayoutReady = vi.fn((callback: () => void) => {
    callback();
  });
  app = appMock.asOriginalType__();

  // Seed the obsidianDevUtilsState holder on the raw target behind the strict-proxy App so the real getObsidianDevUtilsState can read/write it (the proxy throws on first access to an unassigned property).
  seedOnRawTarget(app, 'obsidianDevUtilsState', {});

  // The onloadImpl binds vault.getAvailablePathForAttachments to pass it to AttachmentPathManager; seed it on the raw target so the strict-proxy does not throw.
  seedOnRawTarget(app.vault, 'getAvailablePathForAttachments', vi.fn((): Promise<string> => Promise.resolve('attachments/file.png')));

  // The base's Notebook Navigator registrar reads `app.plugins.getPlugin` once the layout is ready; seed it on the raw target so the strict proxy does not throw. `null` is the "Notebook Navigator is not installed" default.
  getPluginMock = vi.fn((_pluginId: string): null | PluginOriginal => null);
  seedOnRawTarget(app, 'plugins', { getPlugin: getPluginMock });

  // Expose the app as the global instance so dev-utils helpers that resolve shared state without an explicit app argument read/write the same seeded holder.
  castTo<AppGlobal>(window).app = app;
});

function getSettingsBuilder(): () => SettingsBuilderProbe {
  const call = vi.mocked(RenameDeleteHandlerComponent).mock.calls[0];
  if (!call) {
    throw new Error('RenameDeleteHandlerComponent was not constructed.');
  }
  const params = castTo<RenameDeleteHandlerParamsProbe>(call[0]);
  return params.settingsBuilder.bind(params);
}

function seedOnRawTarget(strictProxiedObject: object, key: string, value: unknown): void {
  const proxyWithTarget = castTo<Partial<Record<symbol, object>>>(strictProxiedObject);
  const rawTarget = proxyWithTarget[STRICT_PROXY_TARGET_SYMBOL] ?? strictProxiedObject;
  castTo<Record<string, unknown>>(rawTarget)[key] = value;
}

describe('Plugin', () => {
  it('should wire up all collaborators on load', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();

    expect(plugin).toBeInstanceOf(Plugin);
    expect(PluginSettingsComponent).toHaveBeenCalledOnce();
    expect(TokenValidator).toHaveBeenCalledOnce();
    expect(AttachmentPathManager).toHaveBeenCalledOnce();
    expect(AttachmentRescuer).toHaveBeenCalledOnce();
    expect(ArrayBufferMap).toHaveBeenCalledOnce();
    expect(ImageSizeMap).toHaveBeenCalledOnce();
    expect(MarkdownUrlMap).toHaveBeenCalledOnce();
    expect(ImageManager).toHaveBeenCalledOnce();
    expect(AttachmentSaver).toHaveBeenCalledOnce();
    expect(CustomAttachmentLocationComponent).toHaveBeenCalledOnce();
    expect(PluginSettingsTabComponent).toHaveBeenCalledOnce();
    expect(PluginSettingsTab).toHaveBeenCalledOnce();
    expect(RenameDeleteHandlerComponent).toHaveBeenCalledOnce();
    expect(AttachmentCollector).toHaveBeenCalledOnce();
    expect(UnusedAttachmentsRemover).toHaveBeenCalledOnce();
    // The base separately auto-registers its own handler (e.g. UnlockActiveNoteCommandHandler), so assert the plugin's own registration by its handlers rather than the total call count.
    expect(buildPluginCommandHandlers()).toStrictEqual([
      expect.any(CollectAttachmentsInFileCommandHandler),
      expect.any(DeleteUnusedAttachmentsInFileCommandHandler),
      expect.any(CollectAttachmentsInCurrentFolderCommandHandler),
      expect.any(CollectAttachmentsEntireVaultCommandHandler),
      expect.any(DeleteUnusedAttachmentsEntireVaultCommandHandler),
      expect.any(MoveAttachmentToProperFolderCommandHandler),
      expect.any(GoToAttachmentFolderCommandHandler),
      expect.any(GoToOwningNoteCommandHandler),
      expect.any(OpenDemoVaultCommandHandler)
    ]);
    expect(AppSaveAttachmentPatchComponent).toHaveBeenCalledOnce();
    expect(TokenizedStringLanguageComponent).toHaveBeenCalledOnce();
  });

  describe('collectAttachmentsInAbstractFiles', () => {
    afterEach(() => {
      // The stub below is installed on the module-level mock, so it would leak into every later test.
      vi.mocked(AttachmentCollector).mockReset();
    });

    // The plugin's public surface for other plugins. The command itself acts on the ACTIVE file, so
    // A caller wanting a specific note collected would otherwise have to open it first.
    it('should delegate to the attachment collector', async () => {
      const collectAttachmentsInAbstractFiles = vi.fn();
      // A constructor mock has to be `new`-able, so this cannot be an arrow function. Returning an
      // Object from it overrides the instance, which is how the stub gets in.
      vi.mocked(AttachmentCollector).mockImplementation(castTo<typeof AttachmentCollector>(
        // eslint-disable-next-line prefer-arrow-callback -- An arrow function cannot be `new`-ed, and this stands in for a constructor.
        function mockAttachmentCollector(): AttachmentCollector {
          return castTo<AttachmentCollector>({ collectAttachmentsInAbstractFiles });
        }
      ));

      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      const noteFile = castTo<TFile>({ path: 'note.md' });
      plugin.collectAttachmentsInAbstractFiles([noteFile]);

      expect(collectAttachmentsInAbstractFiles).toHaveBeenCalledWith([noteFile]);
    });

    it('should do nothing when called before the plugin has loaded', async () => {
      // Another plugin can hold a reference across a reload, so this must not throw.
      const plugin = new Plugin(app, manifest);
      expect(() => {
        plugin.collectAttachmentsInAbstractFiles([castTo<TFile>({ path: 'note.md' })]);
      }).not.toThrow();
      await noopAsync();
    });
  });

  it('should register all collect/delete/move command handlers', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();
    buildPluginCommandHandlers();

    expect(CollectAttachmentsInFileCommandHandler).toHaveBeenCalledOnce();
    expect(DeleteUnusedAttachmentsInFileCommandHandler).toHaveBeenCalledOnce();
    expect(CollectAttachmentsInCurrentFolderCommandHandler).toHaveBeenCalledOnce();
    expect(CollectAttachmentsEntireVaultCommandHandler).toHaveBeenCalledOnce();
    expect(MoveAttachmentToProperFolderCommandHandler).toHaveBeenCalledOnce();
  });

  it('should build rename/delete settings reflecting the plugin settings component', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();

    const settings = getSettingsBuilder()();
    expect(settings.emptyFolderBehavior).toBe('Keep');
    expect(settings.shouldUpdateFileNameAliases).toBe(true);
  });

  it('should delegate isNote in the settings builder to the plugin settings component', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();
    hoisted.isNoteEx.mockReturnValue(false);

    const settings = getSettingsBuilder()();
    expect(settings.isNote('note.md')).toBe(false);
    expect(hoisted.isNoteEx).toHaveBeenCalledWith('note.md');
  });

  it('should delegate getRescuePath in the settings builder to the attachment rescuer', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();

    const rescueParams = {
      attachmentPath: 'assets/note-a/shared.png',
      survivingNotePaths: ['note-b.md']
    };
    const settings = getSettingsBuilder()();
    await expect(settings.getRescuePath(rescueParams)).resolves.toBe('assets/note-b/shared.png');
    expect(hoisted.getRescuePath).toHaveBeenCalledWith(rescueParams);
  });

  it('should delegate isPathIgnored in the settings builder to the plugin settings', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();
    hoisted.isPathIgnored.mockReturnValue(true);

    const settings = getSettingsBuilder()();
    expect(settings.isPathIgnored('ignored.md')).toBe(true);
    expect(hoisted.isPathIgnored).toHaveBeenCalledWith('ignored.md');
  });

  // Notebook Navigator draws its own file tree, so it never raises Obsidian's `file-menu` / `files-menu` events.
  // The base binds to its extension API instead, and defers that binding to layout-ready.
  // Each test below therefore has to flush the `LayoutReadyComponent` timer before it can assert.
  describe('Notebook Navigator menu integration', () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    it('should stay dormant when Notebook Navigator is not installed', async () => {
      vi.useFakeTimers();
      const plugin = new Plugin(app, manifest);
      await plugin.onload();
      await vi.runAllTimersAsync();

      expect(getPluginMock).toHaveBeenCalledExactlyOnceWith(NOTEBOOK_NAVIGATOR_PLUGIN_ID);
    });

    it('should register the file and folder menus when Notebook Navigator is installed', async () => {
      const registerFileMenu = vi.fn((): NotebookNavigatorMenuDispose => noop);
      const registerFolderMenu = vi.fn((): NotebookNavigatorMenuDispose => noop);
      // `api` is not part of Obsidian's `Plugin`, so the API carrier can only be handed back through a cast.
      getPluginMock.mockReturnValue(castTo<PluginOriginal>({
        api: {
          menus: {
            registerFileMenu,
            registerFolderMenu
          }
        }
      }));

      vi.useFakeTimers();
      const plugin = new Plugin(app, manifest);
      await plugin.onload();
      await vi.runAllTimersAsync();

      expect(registerFileMenu).toHaveBeenCalledOnce();
      expect(registerFolderMenu).toHaveBeenCalledOnce();
    });
  });

  it('should fall back to an empty plugin directory when the manifest has none', async () => {
    // eslint-disable-next-line unicorn/name-replacements -- `dir` is an Obsidian `PluginManifest` member name.
    const manifestWithoutDirectory = castTo<PluginManifest>({ ...manifest, dir: undefined });
    const plugin = new Plugin(app, manifestWithoutDirectory);
    await plugin.onload();

    const call = vi.mocked(CustomAttachmentLocationComponent).mock.calls[0];
    if (!call) {
      throw new Error('CustomAttachmentLocationComponent was not constructed.');
    }
    const params = castTo<CustomAttachmentLocationParamsProbe>(call[0]);
    expect(params.pluginDirectory).toBe('');
  });
});

// `registerCommandHandlers` takes a factory since obsidian-dev-utils 89.0.0, and the base
// Registers its own handlers through the same spy — so pick the plugin's own factory by what it builds.
function buildPluginCommandHandlers(): CommandHandler[] {
  const commandHandlerBatches = vi.mocked(CommandHandlerComponent.prototype.registerCommandHandlers).mock.calls
    .map(([commandHandlerFactory]) => commandHandlerFactory());
  const pluginCommandHandlers = commandHandlerBatches.find((commandHandlers) => commandHandlers.some((commandHandler) => commandHandler instanceof CollectAttachmentsInFileCommandHandler));
  if (!pluginCommandHandlers) {
    throw new Error('The plugin did not register its own command handlers.');
  }
  return pluginCommandHandlers;
}
