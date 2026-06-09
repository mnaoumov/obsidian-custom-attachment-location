/* eslint-disable @typescript-eslint/no-extraneous-class, @typescript-eslint/no-useless-constructor -- Test mocks require empty constructors. */
import type { TFolder } from 'obsidian';
import type { AbortSignalComponent } from 'obsidian-dev-utils/obsidian/components/abort-signal-component';
import type { ConsoleDebugComponent } from 'obsidian-dev-utils/obsidian/components/console-debug-component';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { Plugin } from '../plugin.ts';

import { collectAttachmentsInAbstractFiles } from '../attachment-collector.ts';

vi.mock('obsidian-dev-utils/obsidian/command-handlers/folder-command-handler', () => ({
  FolderCommandHandler: class {
    public constructor(_params: unknown) {
      // Base no-op.
    }
  }
}));

vi.mock('obsidian-dev-utils/obsidian/i18n/i18n', () => ({
  t: vi.fn((selector: (translations: unknown) => unknown): string => {
    const accessor: unknown = new Proxy((): undefined => undefined, {
      apply: (): string => 'translated',
      get: (): unknown => accessor
    });
    selector(accessor);
    return 'translated';
  })
}));

vi.mock('../attachment-collector.ts', () => ({
  collectAttachmentsInAbstractFiles: vi.fn()
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import { CollectAttachmentsInCurrentFolderCommandHandler } from './collect-attachments-in-current-folder-command-handler.ts';

interface CommandHandlerPrivate {
  executeFolder(folder: TFolder): void;
}

const mockCollectAttachmentsInAbstractFiles = vi.mocked(collectAttachmentsInAbstractFiles);

function asPrivate(handler: CollectAttachmentsInCurrentFolderCommandHandler): CommandHandlerPrivate {
  return castTo<CommandHandlerPrivate>(handler);
}

describe('CollectAttachmentsInCurrentFolderCommandHandler', () => {
  let abortSignalComponent: AbortSignalComponent;
  let consoleDebugComponent: ConsoleDebugComponent;
  let handler: CollectAttachmentsInCurrentFolderCommandHandler;
  let plugin: Plugin;
  let pluginSettingsComponent: PluginSettingsComponent;

  beforeEach(() => {
    vi.clearAllMocks();
    abortSignalComponent = strictProxy<AbortSignalComponent>({});
    consoleDebugComponent = strictProxy<ConsoleDebugComponent>({});
    plugin = strictProxy<Plugin>({});
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({});
    handler = new CollectAttachmentsInCurrentFolderCommandHandler({
      abortSignalComponent,
      consoleDebugComponent,
      plugin,
      pluginSettingsComponent
    });
  });

  it('should create an instance', () => {
    expect(handler).toBeInstanceOf(CollectAttachmentsInCurrentFolderCommandHandler);
  });

  it('should call collectAttachmentsInAbstractFiles with the folder on executeFolder', () => {
    const folder = strictProxy<TFolder>({ path: 'folder' });
    asPrivate(handler).executeFolder(folder);
    expect(mockCollectAttachmentsInAbstractFiles).toHaveBeenCalledExactlyOnceWith(
      plugin,
      [folder],
      abortSignalComponent,
      pluginSettingsComponent,
      consoleDebugComponent
    );
  });
});
/* eslint-enable @typescript-eslint/no-extraneous-class, @typescript-eslint/no-useless-constructor -- End of test file. */
