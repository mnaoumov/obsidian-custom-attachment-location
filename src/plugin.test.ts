import type {
  App as AppOriginal,
  PluginManifest
} from 'obsidian';

import { Component } from 'obsidian';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { CommandHandlerComponent } from 'obsidian-dev-utils/obsidian/command-handlers/command-handler-component';
import { MenuEventRegistrarComponent } from 'obsidian-dev-utils/obsidian/components/menu-event-registrar-component';
import { PluginSettingsTabComponent } from 'obsidian-dev-utils/obsidian/components/plugin-settings-tab-component';
import { RenameDeleteHandlerComponent } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { ArrayBufferMap } from './array-buffer-map.ts';
import { AttachmentCollector } from './attachment-collector.ts';
import { AttachmentPathManager } from './attachment-path-manager.ts';
import { AttachmentSaver } from './attachment-saver.ts';
import { CollectAttachmentsEntireVaultCommandHandler } from './command-handlers/collect-attachments-entire-vault-command-handler.ts';
import { CollectAttachmentsInCurrentFolderCommandHandler } from './command-handlers/collect-attachments-in-current-folder-command-handler.ts';
import { CollectAttachmentsInFileCommandHandler } from './command-handlers/collect-attachments-in-file-command-handler.ts';
import { MoveAttachmentToProperFolderCommandHandler } from './command-handlers/move-attachment-to-proper-folder-command-handler.ts';
import { CustomAttachmentLocationComponent } from './custom-attachment-location-component.ts';
import { ImageManager } from './image-manager.ts';
import { ImageSizeMap } from './image-size-map.ts';
import { MarkdownUrlMap } from './markdown-url-map.ts';
import { AppSaveAttachmentPatchComponent } from './patches/app-save-attachment-patch-component.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import { PluginSettingsTab } from './plugin-settings-tab.ts';
import { PrismComponent } from './prism-component.ts';
import { TokenValidator } from './token-validator.ts';

// --- Hoisted shared state ---

const hoisted = vi.hoisted(() => ({
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

vi.mock('obsidian-dev-utils/obsidian/command-handlers/command-handler-component', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  CommandHandlerComponent: vi.fn(function commandHandlerComponentStub() {
    return new Component();
  })
}));

vi.mock('obsidian-dev-utils/obsidian/components/menu-event-registrar-component', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  MenuEventRegistrarComponent: vi.fn(function menuEventRegistrarComponentStub() {
    return new Component();
  })
}));

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

vi.mock('obsidian-dev-utils/obsidian/active-file-provider', () => ({
  AppActiveFileProvider: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/command-registrar', () => ({
  PluginCommandRegistrar: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/data-handler', () => ({
  PluginDataHandler: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/plugin/plugin-event-source', () => ({
  PluginEventSourceImpl: vi.fn()
}));

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

vi.mock('./prism-component.ts', () => ({
  // eslint-disable-next-line prefer-arrow-callback -- a vi.fn constructor stub must be a function (not an arrow) so `new` works and returns a loadable Component.
  PrismComponent: vi.fn(function prismComponentStub() {
    return new Component();
  })
}));

vi.mock('./token-validator.ts', () => ({
  TokenValidator: vi.fn()
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede the import of the module under test.
import { Plugin } from './plugin.ts';

interface AppGlobal {
  app: AppOriginal;
}

interface CustomAttachmentLocationParamsProbe {
  pluginDir: string;
}

interface RenameDeleteHandlerParamsProbe {
  settingsBuilder(): SettingsBuilderProbe;
}

interface SettingsBuilderProbe {
  emptyFolderBehavior: string;
  isNote(path: string): boolean;
  isPathIgnored(path: string): boolean;
  shouldUpdateFileNameAliases: boolean;
}

const STRICT_PROXY_TARGET_SYMBOL = Symbol.for('strictProxyTarget');

const manifest = castTo<PluginManifest>({
  author: 'test',
  description: 'test',
  dir: 'plugins/custom-attachment-location',
  id: 'custom-attachment-location',
  minAppVersion: '1.0.0',
  name: 'Custom Attachment Location',
  version: '10.0.0'
});

let app: AppOriginal;

beforeEach(() => {
  vi.clearAllMocks();
  hoisted.isNoteEx.mockReturnValue(true);
  hoisted.isPathIgnored.mockReturnValue(false);
  const appMock = App.createConfigured__();
  appMock.workspace.onLayoutReady = vi.fn((cb: () => void) => {
    cb();
  });
  app = appMock.asOriginalType__();

  // Seed the obsidianDevUtilsState holder on the raw target behind the strict-proxy App so the real getObsidianDevUtilsState can read/write it (the proxy throws on first access to an unassigned property).
  seedOnRawTarget(app, 'obsidianDevUtilsState', {});

  // The onloadImpl binds vault.getAvailablePathForAttachments to pass it to AttachmentPathManager; seed it on the raw target so the strict-proxy does not throw.
  seedOnRawTarget(app.vault, 'getAvailablePathForAttachments', vi.fn((): Promise<string> => Promise.resolve('attachments/file.png')));

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
    expect(MenuEventRegistrarComponent).toHaveBeenCalledOnce();
    expect(CommandHandlerComponent).toHaveBeenCalledOnce();
    expect(AppSaveAttachmentPatchComponent).toHaveBeenCalledOnce();
    expect(PrismComponent).toHaveBeenCalledOnce();
  });

  it('should register all four collect/move command handlers', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();

    expect(CollectAttachmentsInFileCommandHandler).toHaveBeenCalledOnce();
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

  it('should delegate isPathIgnored in the settings builder to the plugin settings', async () => {
    const plugin = new Plugin(app, manifest);
    await plugin.onload();
    hoisted.isPathIgnored.mockReturnValue(true);

    const settings = getSettingsBuilder()();
    expect(settings.isPathIgnored('ignored.md')).toBe(true);
    expect(hoisted.isPathIgnored).toHaveBeenCalledWith('ignored.md');
  });

  it('should fall back to an empty plugin directory when the manifest has none', async () => {
    const manifestWithoutDir = castTo<PluginManifest>({ ...manifest, dir: undefined });
    const plugin = new Plugin(app, manifestWithoutDir);
    await plugin.onload();

    const call = vi.mocked(CustomAttachmentLocationComponent).mock.calls[0];
    if (!call) {
      throw new Error('CustomAttachmentLocationComponent was not constructed.');
    }
    const params = castTo<CustomAttachmentLocationParamsProbe>(call[0]);
    expect(params.pluginDir).toBe('');
  });
});
