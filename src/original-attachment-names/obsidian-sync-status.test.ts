import type {
  SyncFilter,
  SyncPluginInstance
} from '@obsidian-typings/obsidian-public-latest';
import type { App } from 'obsidian';

import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  describe,
  expect,
  it,
  vi
} from 'vitest';

import {
  getObsidianSyncStatus,
  ObsidianSyncState
} from './obsidian-sync-status.ts';

interface CreatedApp {
  readonly app: App;
  readonly getEnabledPluginById: (id: string) => unknown;
}

function createApp(syncInstance: unknown): CreatedApp {
  const getEnabledPluginById = vi.fn((_id: string): unknown => syncInstance);
  const app = strictProxy<App>({
    internalPlugins: strictProxy<App['internalPlugins']>({
      getEnabledPluginById: castTo<App['internalPlugins']['getEnabledPluginById']>(getEnabledPluginById)
    })
  });
  return { app, getEnabledPluginById };
}

describe('getObsidianSyncStatus', () => {
  it('reports Off when the core Sync plugin is disabled, and answers no carry question', () => {
    const { app, getEnabledPluginById } = createApp(null);
    const status = getObsidianSyncStatus(app);
    expect(getEnabledPluginById).toHaveBeenCalledWith('sync');
    expect(status.state).toBe(ObsidianSyncState.Off);
    expect(status.doesCarryFile('a/b.json')).toBeUndefined();
  });

  it.each([
    ['no remote vault id', null],
    ['an empty remote vault id', '']
  ])('reports NotConnected for %s', (_label, remoteVaultId) => {
    const instance = strictProxy<SyncPluginInstance>({ getRemoteVaultId: (): null | string => remoteVaultId });
    const status = getObsidianSyncStatus(createApp(instance).app);
    expect(status.state).toBe(ObsidianSyncState.NotConnected);
    expect(status.doesCarryFile('a/b.json')).toBeUndefined();
  });

  it.each([true, false])('asks the selective-sync filter whether a file is carried (%s)', (isCarried) => {
    const filter = strictProxy<SyncFilter>({
      allowSyncFile: vi.fn(function allowsSyncFile(this: SyncFilter, _path: string, _isFolder: boolean): boolean {
        expect(this).toBe(filter);
        return isCarried;
      })
    });
    const instance = strictProxy<SyncPluginInstance>({ filter, getRemoteVaultId: (): string => 'remote' });
    const status = getObsidianSyncStatus(createApp(instance).app);
    expect(status.state).toBe(ObsidianSyncState.Connected);
    expect(status.doesCarryFile('a/b.json')).toBe(isCarried);
    expect(filter.allowSyncFile).toHaveBeenCalledWith('a/b.json', false);
  });
});
