import type { CommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/command-handler';
import type {
  PluginConflict,
  PluginDependency,
  PluginGateComponent
} from '@mnaoumov/obsidian-lib/components/plugin-gate-component';
import type { NotebookNavigatorMenuDispose } from '@mnaoumov/obsidian-lib/notebook-navigator';
import type { ApiContract } from '@mnaoumov/typescript-lib/api-contract';
import type { DisposableEx } from '@mnaoumov/typescript-lib/disposable';
/* eslint-disable perfectionist/sort-named-imports -- dprint orders these members by their ORIGINAL name (`Plugin` before `PluginManifest`) while perfectionist orders them by the LOCAL alias (`PluginManifest` before `PluginOriginal`). For an aliased import the two orders conflict, and satisfying one re-breaks the other. */
import type {
  App as AppOriginal,
  Plugin as PluginOriginal,
  PluginManifest,
  TFile
} from 'obsidian';
/* eslint-enable perfectionist/sort-named-imports -- Only the aliased import above is exempt. */
import type { Mock } from 'vitest';

import { CommandHandlerComponent } from '@mnaoumov/obsidian-lib/command-handlers/command-handler-component';
import { OpenDemoVaultCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/open-demo-vault-command-handler';
import { UndoBulkOperationCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/undo-bulk-operation-command-handler';
import { PluginConflictSeverity } from '@mnaoumov/obsidian-lib/components/plugin-gate-component';
import { PluginSettingsTabComponent } from '@mnaoumov/obsidian-lib/components/plugin-settings-tab-component';
import { RenameDeleteHandlerComponent } from '@mnaoumov/obsidian-lib/components/rename-delete-handler-component';
import { SettingsMigrationComponent } from '@mnaoumov/obsidian-lib/components/settings-migration-component';
import { NOTEBOOK_NAVIGATOR_PLUGIN_ID } from '@mnaoumov/obsidian-lib/notebook-navigator';
import {
  publishPluginApi,
  watchPluginApi
} from '@mnaoumov/obsidian-lib/plugin/plugin-api';
import {
  noop,
  noopAsync
} from '@mnaoumov/typescript-lib/function';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { Component } from 'obsidian';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { MigratableSettings } from './advanced-rename-and-delete-handler/advanced-rename-and-delete-handler.ts';
import type { CustomAttachmentLocationApi } from './plugin-api/plugin-api.ts';

import { ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT } from './advanced-rename-and-delete-handler/api/api-contract.ts';
import { HandedOverSettingsComponent } from './advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import { AttachmentPathManager } from './attachment-location/attachment-path-manager.ts';
import { CustomAttachmentLocationComponent } from './attachment-location/custom-attachment-location-component.ts';
import { AppSaveAttachmentPatchComponent } from './attachment-saving/app-save-attachment-patch-component.ts';
import { ArrayBufferMap } from './attachment-saving/array-buffer-map.ts';
import { AttachmentSaver } from './attachment-saving/attachment-saver.ts';
import { ImageManager } from './attachment-saving/image-manager.ts';
import { AttachmentCollector } from './collect/attachment-collector.ts';
import { CollectAttachmentsEntireVaultCommandHandler } from './collect/collect-attachments-entire-vault-command-handler.ts';
import { CollectAttachmentsInCurrentFolderCommandHandler } from './collect/collect-attachments-in-current-folder-command-handler.ts';
import { CollectAttachmentsInFileCommandHandler } from './collect/collect-attachments-in-file-command-handler.ts';
import { DeleteUnusedAttachmentsEntireVaultCommandHandler } from './delete-unused-attachments/delete-unused-attachments-entire-vault-command-handler.ts';
import { DeleteUnusedAttachmentsInFileCommandHandler } from './delete-unused-attachments/delete-unused-attachments-in-file-command-handler.ts';
import { UnusedAttachmentsRemover } from './delete-unused-attachments/unused-attachments-remover.ts';
import { ImageSizeMap } from './markdown-links/image-size-map.ts';
import { MarkdownUrlMap } from './markdown-links/markdown-url-map.ts';
import { MoveAttachmentToProperFolderCommandHandler } from './move-attachment-to-proper-folder/move-attachment-to-proper-folder-command-handler.ts';
import { GoToAttachmentFolderCommandHandler } from './navigation/go-to-attachment-folder-command-handler.ts';
import { GoToOwningNoteCommandHandler } from './navigation/go-to-owning-note-command-handler.ts';
import { PruneOriginalAttachmentNamesCommandHandler } from './original-attachment-names/prune-original-attachment-names-command-handler.ts';
import { RememberCurrentNameAsOriginalCommandHandler } from './original-attachment-names/remember-current-name-as-original-command-handler.ts';
import { ShowOriginalAttachmentNamesCommandHandler } from './original-attachment-names/show-original-attachment-names-command-handler.ts';
import { PLUGIN_API_CONTRACT } from './plugin-api/plugin-api.ts';
import { createReleaseNotesComponent } from './release-notes-component.ts';
import { PluginSettingsComponent } from './settings/plugin-settings-component.ts';
import { PluginSettingsTab } from './settings/plugin-settings-tab.ts';
import { TokenValidator } from './tokens/token-validator.ts';
import { createTokenizedStringLanguageComponent } from './tokens/tokenized-string-language.ts';

// --- Hoisted shared state ---

interface StubbedSettings {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  proposedRenameDeleteSettings: MigratableSettings | null;
}

const hoisted = vi.hoisted(() => {
  // Annotated rather than inferred: the pending value starts `null`, and an inferred literal type would
  // make it permanently `null`, so no test could park a proposal in it.
  const settings: StubbedSettings = {
    proposedRenameDeleteSettings: null
  };
  return {
    editAndSave: vi.fn((settingsEditor: (settings: StubbedSettings) => void): Promise<void> => {
      settingsEditor(settings);
      return noopAsync();
    }),
    isNoteEx: vi.fn((_path: string): boolean => true),
    settings
  };
});

// --- Collaborator obsidian-lib components added as children: stub as constructor spies returning a real Component so the real addChild lifecycle can load them while capturing constructor args. ---

vi.mock('@mnaoumov/obsidian-lib/components/plugin-settings-tab-component', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  PluginSettingsTabComponent: vi.fn(function pluginSettingsTabComponentStub() {
    return new Component();
  })
}));

vi.mock('@mnaoumov/obsidian-lib/components/rename-delete-handler-component', async (importOriginal) => {
  const original = await importOriginal<typeof import('@mnaoumov/obsidian-lib/components/rename-delete-handler-component')>();
  return {
    ...original,
    // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
    RenameDeleteHandlerComponent: vi.fn(function renameDeleteHandlerComponentStub() {
      return new Component();
    })
  };
});

// --- Collaborator obsidian-lib components NOT added as children: bare constructor spies. ---

// `PluginDataHandler` and `PluginEventSourceImpl` are NOT stubbed: the base
// builds its own settings component out of them during `onload`, and that component really calls
// `pluginEventSource.on`, so a bare `vi.fn()` double makes the base throw before `onloadImpl` runs.
// --- The plugin's OWN sibling modules: collaborators added as children return a real Component; the rest are bare constructor spies. ---

vi.mock('./advanced-rename-and-delete-handler/handed-over-settings-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  HandedOverSettingsComponent: vi.fn(function handedOverSettingsComponentStub() {
    return new Component();
  })
}));

vi.mock('@mnaoumov/obsidian-lib/components/settings-migration-component', async (importOriginal) => {
  const original = await importOriginal<typeof import('@mnaoumov/obsidian-lib/components/settings-migration-component')>();
  return {
    ...original,
    // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
    SettingsMigrationComponent: vi.fn(function settingsMigrationComponentStub() {
      return new Component();
    })
  };
});

vi.mock('./attachment-saving/array-buffer-map.ts', () => ({
  ArrayBufferMap: vi.fn()
}));

vi.mock('./collect/attachment-collector.ts', () => ({
  AttachmentCollector: vi.fn()
}));

vi.mock('./attachment-location/attachment-path-manager.ts', () => ({
  AttachmentPathManager: vi.fn()
}));

vi.mock('./attachment-saving/attachment-saver.ts', () => ({
  AttachmentSaver: vi.fn()
}));

vi.mock('./sidecars/sidecar-attachments-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- A constructor stub returns a real loadable component, matching the other collaborator fixtures.
  SidecarAttachmentsComponent: vi.fn(function sidecarAttachmentsComponentStub() {
    return new Component();
  })
}));

vi.mock('./collect/collect-attachments-entire-vault-command-handler.ts', () => ({
  CollectAttachmentsEntireVaultCommandHandler: vi.fn()
}));

vi.mock('./collect/collect-attachments-in-current-folder-command-handler.ts', () => ({
  CollectAttachmentsInCurrentFolderCommandHandler: vi.fn()
}));

vi.mock('./collect/collect-attachments-in-file-command-handler.ts', () => ({
  CollectAttachmentsInFileCommandHandler: vi.fn()
}));

vi.mock('./delete-unused-attachments/delete-unused-attachments-in-file-command-handler.ts', () => ({
  DeleteUnusedAttachmentsInFileCommandHandler: vi.fn()
}));

vi.mock('./navigation/go-to-attachment-folder-command-handler.ts', () => ({
  GoToAttachmentFolderCommandHandler: vi.fn()
}));

vi.mock('./navigation/go-to-owning-note-command-handler.ts', () => ({
  GoToOwningNoteCommandHandler: vi.fn()
}));

vi.mock('./move-attachment-to-proper-folder/move-attachment-to-proper-folder-command-handler.ts', () => ({
  MoveAttachmentToProperFolderCommandHandler: vi.fn()
}));

vi.mock('./attachment-location/custom-attachment-location-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  CustomAttachmentLocationComponent: vi.fn(function customAttachmentLocationComponentStub() {
    return new Component();
  })
}));

vi.mock('./attachment-saving/image-manager.ts', () => ({
  ImageManager: vi.fn()
}));

vi.mock('./markdown-links/image-size-map.ts', () => ({
  ImageSizeMap: vi.fn()
}));

vi.mock('./markdown-links/markdown-url-map.ts', () => ({
  MarkdownUrlMap: vi.fn()
}));

vi.mock('./attachment-saving/app-save-attachment-patch-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  AppSaveAttachmentPatchComponent: vi.fn(function appSaveAttachmentPatchComponentStub() {
    return new Component();
  })
}));

vi.mock('./settings/plugin-settings-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component carrying the stubbed settings.
  PluginSettingsComponent: vi.fn(function pluginSettingsComponentStub() {
    const component = new Component();
    Object.assign(component, {
      editAndSave: (settingsEditor: (settings: typeof hoisted.settings) => void): Promise<void> => hoisted.editAndSave(settingsEditor),
      isNoteEx: (path: string): boolean => hoisted.isNoteEx(path),
      settings: hoisted.settings
    });
    return component;
  })
}));

vi.mock('./settings/plugin-settings-tab.ts', () => ({
  PluginSettingsTab: vi.fn()
}));

vi.mock('./release-notes-component.ts', () => ({
  createReleaseNotesComponent: vi.fn(() => new Component())
}));

vi.mock('./tokens/tokenized-string-language.ts', () => ({
  createTokenizedStringLanguageComponent: vi.fn(() => new Component())
}));

vi.mock('./tokens/token-validator.ts', () => ({
  TokenValidator: vi.fn()
}));

vi.mock('./delete-unused-attachments/unused-attachments-remover.ts', () => ({
  UnusedAttachmentsRemover: vi.fn()
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede the import of the module under test.
import { Plugin } from './plugin.ts';

// The base pre-wires `commandHandlerComponent`; stub its `registerCommandHandlers` so the plugin's registration is asserted without exercising the mocked command handlers.
vi.spyOn(CommandHandlerComponent.prototype, 'registerCommandHandlers').mockResolvedValue(castTo<DisposableEx>({ dispose: vi.fn() }));

interface AppGlobal {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  app: AppOriginal;
}

interface MigrationParamsProbe {
  readonly apiVersionRange: string;
  readonly contract: ApiContract;
  readonly getProposedSettings: () => MigratableSettings | null;
  readonly providerPluginId: string;
  readonly retireProposedSettings: () => Promise<void>;
  readonly sourcePluginId: string;
}

// `getPluginApis` is protected on the base, so a test reads it through a probe.
interface PluginApisProbe {
  readonly getPluginApis: () => unknown[];
}

// `getPluginConflicts` is protected on the base — the declaration is for the library, not for callers —
// so a test reads it through a probe rather than widening the plugin's own surface.
interface PluginConflictsProbe {
  readonly getPluginConflicts: () => PluginConflict[];
}

// `getPluginDependencies` is protected on the base, so a test reads it through a probe.
interface PluginDependenciesProbe {
  readonly getPluginDependencies: () => PluginDependency[];
}

interface PluginGateProbe {
  readonly pluginGateComponent: PluginGateComponent;
}

interface ReleaseNotesParamsProbe {
  readonly pluginDirectory: string;
  readonly pluginName: string;
}

interface SettingsTabParamsProbe {
  readonly getPluginGateComponent: () => PluginGateComponent;
}

function getMigrationParams(): MigrationParamsProbe {
  const call = vi.mocked(SettingsMigrationComponent).mock.calls[0];
  if (!call) {
    throw new Error('SettingsMigrationComponent was not constructed.');
  }
  return castTo<MigrationParamsProbe>(call[0]);
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

// The contract the stand-in provider publishes: the lowest one the dependency accepts.
const PROVIDER_API_VERSION = '1.1.0';

let app: AppOriginal;
let getPluginMock: Mock<(pluginId: string) => null | PluginOriginal>;
let providerComponent: Component;

beforeEach(() => {
  vi.clearAllMocks();
  hoisted.isNoteEx.mockReturnValue(true);
  // A plain object, so `clearAllMocks` does not reset it and a test that flips a value would leak.
  hoisted.settings.proposedRenameDeleteSettings = null;
  const appMock = App.createConfigured__();
  appMock.workspace.onLayoutReady = vi.fn((callback: () => void) => {
    callback();
  });
  app = appMock.asOriginalType__();

  // The onloadImpl binds vault.getAvailablePathForAttachments to pass it to AttachmentPathManager; seed it on the raw target so the strict-proxy does not throw.
  seedOnRawTarget(app.vault, 'getAvailablePathForAttachments', vi.fn((): Promise<string> => Promise.resolve('attachments/file.png')));

  // The base's Notebook Navigator registrar reads `app.plugins.getPlugin` once the layout is ready. `obsidian-test-mocks` models the registry now and already answers `null` there, so this seeds only `getPlugin` on it rather than replacing the whole registry: the tests below assert on the calls and re-point the return value, which a bare `registerPlugin__` cannot express.
  getPluginMock = vi.fn((_pluginId: string): null | PluginOriginal => null);
  seedOnRawTarget(app.plugins, 'getPlugin', getPluginMock);

  // Expose the app as the global instance so obsidian-lib helpers that resolve shared state without an explicit app argument read/write the same seeded holder.
  castTo<AppGlobal>(window).app = app;

  // What the dependency gate reaches when the dependency is missing: it registers a settings tab explaining
  // what to install. `obsidian-test-mocks` does not model `app.setting`.
  seedOnRawTarget(app, 'setting', {
    addSettingTab: vi.fn(),
    removeSettingTab: vi.fn()
  });

  // `Advanced Rename and Delete Handler` is a declared dependency, so the feature surface — everything these
  // tests look at — loads only once its API is published. An empty API is enough: the gate checks only that
  // one is there, at a matching version. Each test gets a fresh app, and with it a fresh registry.
  providerComponent = new Component();
  providerComponent.load();
  publishPluginApi({
    api: {},
    apiVersion: PROVIDER_API_VERSION,
    component: providerComponent,
    plugin: castTo<PluginOriginal>({ manifest: { id: 'advanced-rename-and-delete-handler' } })
  });
});

function seedOnRawTarget(strictProxiedObject: object, key: string, value: unknown): void {
  const proxyWithTarget = castTo<Partial<Record<symbol, object>>>(strictProxiedObject);
  const rawTarget = proxyWithTarget[STRICT_PROXY_TARGET_SYMBOL] ?? strictProxiedObject;
  castTo<Record<string, unknown>>(rawTarget)[key] = value;
}

/**
 * Withdraws the stand-in provider's API, as `Advanced Rename and Delete Handler` being disabled would.
 */
function unpublishProviderApi(): void {
  providerComponent.unload();
}

describe('Plugin', () => {
  it('should wire up all collaborators on load', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();

    expect(plugin).toBeInstanceOf(Plugin);
    expect(PluginSettingsComponent).toHaveBeenCalledOnce();
    expect(TokenValidator).toHaveBeenCalledOnce();
    expect(AttachmentPathManager).toHaveBeenCalledOnce();
    expect(ArrayBufferMap).toHaveBeenCalledOnce();
    expect(ImageSizeMap).toHaveBeenCalledOnce();
    expect(MarkdownUrlMap).toHaveBeenCalledOnce();
    expect(ImageManager).toHaveBeenCalledOnce();
    expect(AttachmentSaver).toHaveBeenCalledOnce();
    expect(CustomAttachmentLocationComponent).toHaveBeenCalledOnce();
    expect(PluginSettingsTabComponent).toHaveBeenCalledOnce();
    expect(PluginSettingsTab).toHaveBeenCalledOnce();
    // The whole point of 12.0.0: rename/delete belongs to `Advanced Rename and Delete Handler`, and two
    // handlers acting on one rename corrupt links. This plugin must register NONE.
    expect(RenameDeleteHandlerComponent).not.toHaveBeenCalled();
    expect(HandedOverSettingsComponent).toHaveBeenCalledOnce();
    expect(SettingsMigrationComponent).toHaveBeenCalledOnce();
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
      expect.any(ShowOriginalAttachmentNamesCommandHandler),
      expect.any(PruneOriginalAttachmentNamesCommandHandler),
      expect.any(RememberCurrentNameAsOriginalCommandHandler),
      expect.any(UndoBulkOperationCommandHandler),
      expect.any(OpenDemoVaultCommandHandler)
    ]);
    expect(AppSaveAttachmentPatchComponent).toHaveBeenCalledOnce();
    expect(createTokenizedStringLanguageComponent).toHaveBeenCalledOnce();
  });

  describe('Consistent Attachments and Links overlap', () => {
    it('should declare it as a warning rather than a refusal to run', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      const conflicts = castTo<PluginConflictsProbe>(plugin).getPluginConflicts();

      expect(conflicts).toHaveLength(1);
      const [conflict] = conflicts;
      expect(conflict?.pluginId).toBe('consistent-attachments-and-links');
      expect(conflict?.pluginName).toBe('Consistent Attachments and Links');
      // Duplicate palette entries and doubled work are annoying, not vault-corrupting, so both plugins
      // keep running.
      expect(conflict?.severity).toBe(PluginConflictSeverity.Warn);
      // A RANGE closed at that plugin's next major, not a minimum: the release that drops collecting has
      // not shipped, so every released version still overlaps.
      expect(conflict?.conflictingVersionRange).toBe('<5.0.0');
      expect(conflict?.reason).toContain('Collect attachments in entire vault');
    });

    // The settings tab takes an ACCESSOR rather than the gate itself: the gate is what loads the feature
    // surface, so at the moment `onloadImpl` builds the tab the base has not assigned it yet, and reading
    // it eagerly throws.
    it('should hand the settings tab a lazy route to the plugin gate', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      const call = vi.mocked(PluginSettingsTab).mock.calls[0];
      if (!call) {
        throw new Error('PluginSettingsTab was not constructed.');
      }

      const params = castTo<SettingsTabParamsProbe>(call[0]);
      expect(params.getPluginGateComponent()).toBe(castTo<PluginGateProbe>(plugin).pluginGateComponent);
    });
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
      // object from it overrides the instance, which is how the stub gets in.
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

    // The public method reads a field that outlives the feature surface, which unloads whenever the dependency
    // goes away. Without the reset it would drive a collector whose components have been torn down.
    it('should stop collecting once the dependency goes away', async () => {
      const collectAttachmentsInAbstractFiles = vi.fn();
      vi.mocked(AttachmentCollector).mockImplementation(castTo<typeof AttachmentCollector>(
        // eslint-disable-next-line prefer-arrow-callback -- An arrow function cannot be `new`-ed, and this stands in for a constructor.
        function mockAttachmentCollector(): AttachmentCollector {
          return castTo<AttachmentCollector>({ collectAttachmentsInAbstractFiles });
        }
      ));
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      unpublishProviderApi();
      plugin.collectAttachmentsInAbstractFiles([castTo<TFile>({ path: 'note.md' })]);

      expect(collectAttachmentsInAbstractFiles).not.toHaveBeenCalled();
      plugin.unload();
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

  describe('published API', () => {
    /*
     * The per-note read exists BECAUSE the `Vault.getConfig` patch cannot answer for a note that is not
     * open. That defect is proved end to end in
     * `src/plugin-api/plugin-api-per-note-folder.desktop.integration.test.ts`; what is asserted here is only that the
     * declaration reaches the registry at all, which is the half a consumer negotiates against.
     */
    it('should publish its reads through the registry, at the declared contract', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      const consumerComponent = new Component();
      consumerComponent.load();
      const apiRef = watchPluginApi<CustomAttachmentLocationApi>({
        apiVersionRange: '^1',
        app,
        component: consumerComponent,
        pluginId: manifest.id
      });

      expect(apiRef.value).not.toBeNull();
      for (const methodName of Object.keys(PLUGIN_API_CONTRACT)) {
        expect(apiRef.value).toHaveProperty(methodName, expect.any(Function));
      }

      consumerComponent.unload();
      plugin.unload();
    });

    // The declaration is tied to the feature surface, so a consumer sees the API GO AWAY rather than
    // answering from components the dependency gate has torn down.
    it('should revoke the handle once the dependency goes away', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      const consumerComponent = new Component();
      consumerComponent.load();
      const apiRef = watchPluginApi<CustomAttachmentLocationApi>({
        apiVersionRange: '^1',
        app,
        component: consumerComponent,
        pluginId: manifest.id
      });
      expect(apiRef.value).not.toBeNull();

      unpublishProviderApi();

      expect(apiRef.value).toBeNull();
      consumerComponent.unload();
      plugin.unload();
    });

    // The base asks for the declaration only right after `onloadImpl` has built the API, so no public path
    // reaches the empty answer; it is what the declaration says while the surface is down, asked directly.
    it('should declare no API while the dependency is away', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();
      expect(castTo<PluginApisProbe>(plugin).getPluginApis()).toHaveLength(1);

      unpublishProviderApi();

      expect(castTo<PluginApisProbe>(plugin).getPluginApis()).toEqual([]);
      plugin.unload();
    });
  });

  describe('Advanced Rename and Delete Handler dependency', () => {
    it('should declare the plugin that now owns rename/delete as a dependency it cannot run without', () => {
      const plugin = new Plugin(app, manifest);

      const [dependency, ...rest] = castTo<PluginDependenciesProbe>(plugin).getPluginDependencies();

      expect(rest).toEqual([]);
      expect(dependency?.pluginId).toBe('advanced-rename-and-delete-handler');
      expect(dependency?.pluginName).toBe('Advanced Rename and Delete Handler');
      // `1.1.0` rather than `^1`: the read-back arrived in that contract, and an older provider would open the
      // gate and then fail every read.
      expect(dependency?.apiVersionRange).toBe('^1.1.0');
      // 2.1.x publishes that same contract but reads the unit-folder designation off a graft this plugin removed,
      // so only the plugin version tells it apart. Up to 3.0.0 it publishes into the registry obsidian-lib 6
      // stopped reading, so 3.0.1 is the first release this plugin can see at all.
      expect(dependency?.minPluginVersion).toBe('3.0.1');
      // Both plugin names are marked as code, so the reason is a fragment rather than a plain string.
      const reason = dependency?.reason;
      expect(reason).toBeInstanceOf(DocumentFragment);
      const reasonFragment = castTo<DocumentFragment>(reason);
      expect(reasonFragment.textContent).toContain('no longer handles renames and deletions itself.');
      expect(Array.from(reasonFragment.querySelectorAll('code'), (codeEl) => codeEl.textContent)).toEqual([
        manifest.name,
        'Advanced Rename and Delete Handler'
      ]);
    });

    it('should load nothing of its own while the dependency is missing', async () => {
      unpublishProviderApi();
      const plugin = new Plugin(app, manifest);

      await plugin.onload();

      expect(PluginSettingsComponent).not.toHaveBeenCalled();
      expect(AttachmentCollector).not.toHaveBeenCalled();
      expect(AppSaveAttachmentPatchComponent).not.toHaveBeenCalled();
      plugin.unload();
    });
  });

  describe('Advanced Rename and Delete Handler settings migration', () => {
    it('should offer the migration to the plugin that now owns rename/delete', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      const params = getMigrationParams();
      expect(params.providerPluginId).toBe('advanced-rename-and-delete-handler');
      expect(params.sourcePluginId).toBe(manifest.id);
      expect(params.apiVersionRange).toBe('^1');
    });

    // The migration names only the method it calls. Which provider versions are good enough is the dependency
    // gate's question, answered by its own version range, not by this contract. The entry is the provider's own,
    // schemas included.
    it('should demand only the method it calls, migrateSettings', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      expect(getMigrationParams().contract).toStrictEqual({ migrateSettings: ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.migrateSettings });
    });

    it('should offer nothing while no legacy values are pending', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      expect(getMigrationParams().getProposedSettings()).toBeNull();
    });

    it('should offer the pending values once the settings carry them', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();

      const proposal = { shouldHandleDeletions: true, shouldHandleRenames: true };
      hoisted.settings.proposedRenameDeleteSettings = proposal;

      expect(getMigrationParams().getProposedSettings()).toBe(proposal);
    });

    // `editAndSave`, not `setProperty`: a retirement that only edits the in-memory state is forgotten on the
    // next reload, so an applied migration would be offered forever.
    it('should persist the retirement rather than only holding it in memory', async () => {
      const plugin = new Plugin(app, manifest);
      await plugin.onload();
      hoisted.settings.proposedRenameDeleteSettings = { shouldHandleRenames: true };
      hoisted.editAndSave.mockClear();

      await getMigrationParams().retireProposedSettings();

      expect(hoisted.editAndSave).toHaveBeenCalledOnce();
      expect(hoisted.settings.proposedRenameDeleteSettings).toBeNull();
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

  // Notebook Navigator draws its own file tree, so it never raises Obsidian's `file-menu` / `files-menu` events.
  // The base binds to its extension API instead, and defers that binding to layout-ready.
  // Each test below therefore has to flush the `LayoutReadyComponent` timer before it can assert.
  describe('Notebook Navigator menu integration', () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    it('should stay dormant when Notebook Navigator is not installed', async () => {
      vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
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

      vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
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

    const call = vi.mocked(createReleaseNotesComponent).mock.calls[0];
    if (!call) {
      throw new Error('The release notes component was not created.');
    }
    const params = castTo<ReleaseNotesParamsProbe>(call[0]);
    expect(params.pluginDirectory).toBe('');
  });

  it('should name the plugin in the release notes', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();

    const call = vi.mocked(createReleaseNotesComponent).mock.calls[0];
    if (!call) {
      throw new Error('The release notes component was not created.');
    }
    const params = castTo<ReleaseNotesParamsProbe>(call[0]);
    expect(params.pluginName).toBe(manifest.name);
  });
});

// `registerCommandHandlers` takes a factory, and the base
// registers its own handlers through the same spy — so pick the plugin's own factory by what it builds.
function buildPluginCommandHandlers(): CommandHandler[] {
  const commandHandlerBatches = vi.mocked(CommandHandlerComponent.prototype.registerCommandHandlers).mock.calls
    .map(([commandHandlerFactory]) => commandHandlerFactory());
  const pluginCommandHandlers = commandHandlerBatches.find((commandHandlers) => commandHandlers.some((commandHandler) => commandHandler instanceof CollectAttachmentsInFileCommandHandler));
  if (!pluginCommandHandlers) {
    throw new Error('The plugin did not register its own command handlers.');
  }
  return pluginCommandHandlers;
}
