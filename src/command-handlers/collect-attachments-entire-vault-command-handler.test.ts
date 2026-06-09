/* eslint-disable @typescript-eslint/no-extraneous-class, @typescript-eslint/no-useless-constructor -- Test mocks require empty constructors. */
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

import { collectAttachmentsEntireVault } from '../attachment-collector.ts';

vi.mock('obsidian-dev-utils/obsidian/command-handlers/global-command-handler', () => ({
  GlobalCommandHandler: class {
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
  collectAttachmentsEntireVault: vi.fn()
}));

// eslint-disable-next-line import-x/first, import-x/imports-first -- vi.mock must precede imports.
import { CollectAttachmentsEntireVaultCommandHandler } from './collect-attachments-entire-vault-command-handler.ts';

interface CommandHandlerPrivate {
  execute(): Promise<void>;
}

const mockCollectAttachmentsEntireVault = vi.mocked(collectAttachmentsEntireVault);

function asPrivate(handler: CollectAttachmentsEntireVaultCommandHandler): CommandHandlerPrivate {
  return castTo<CommandHandlerPrivate>(handler);
}

describe('CollectAttachmentsEntireVaultCommandHandler', () => {
  let abortSignalComponent: AbortSignalComponent;
  let consoleDebugComponent: ConsoleDebugComponent;
  let handler: CollectAttachmentsEntireVaultCommandHandler;
  let plugin: Plugin;
  let pluginSettingsComponent: PluginSettingsComponent;

  beforeEach(() => {
    vi.clearAllMocks();
    abortSignalComponent = strictProxy<AbortSignalComponent>({});
    consoleDebugComponent = strictProxy<ConsoleDebugComponent>({});
    plugin = strictProxy<Plugin>({});
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({});
    handler = new CollectAttachmentsEntireVaultCommandHandler({
      abortSignalComponent,
      consoleDebugComponent,
      plugin,
      pluginSettingsComponent
    });
  });

  it('should create an instance', () => {
    expect(handler).toBeInstanceOf(CollectAttachmentsEntireVaultCommandHandler);
  });

  it('should call collectAttachmentsEntireVault with the wired components on execute', async () => {
    await asPrivate(handler).execute();
    expect(mockCollectAttachmentsEntireVault).toHaveBeenCalledExactlyOnceWith(
      plugin,
      abortSignalComponent,
      pluginSettingsComponent,
      consoleDebugComponent
    );
  });
});
/* eslint-enable @typescript-eslint/no-extraneous-class, @typescript-eslint/no-useless-constructor -- End of test file. */
