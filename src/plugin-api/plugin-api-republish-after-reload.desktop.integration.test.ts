import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * An update and a Hot Reload both unload the running instance and load a new one, and the owner sees them in a row.
 * `@mnaoumov/obsidian-lib` before 10.12.0 let an instance unloaded in the middle of its own load publish its API
 * anyway, on a component that never unloads again. The next instance's publish then threw
 * `The plugin "obsidian-custom-attachment-location" has already published the API version ...` and the plugin stayed
 * unloaded until Obsidian restarted.
 *
 * This small vault loads too fast to land a disable inside `onloadImpl` reliably, so this suite does not reproduce that
 * race: the library's own unit tests do. It holds the outcome the user sees: reloads in a row, including ones that
 * unload an instance whose load has not finished, each end with the API published.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
// Six waits must stay under the transport's ~30s per-closure cap; each is one plugin reload in a small vault.
const WAIT_TIMEOUT_IN_MILLISECONDS = 3000;
const RELOAD_COUNT = 2;

interface ReloadResult {
  readonly cutShortReloads: boolean[];
  readonly plainReloads: boolean[];
}

describe('The plugin API across reloads', () => {
  it('is published again after every reload, including one that cuts the previous load short', async () => {
    const result = await evalInObsidian({
      async callback({ app, lib: { waitUntil }, pluginId, reloadCount, waitTimeoutInMilliseconds }): Promise<ReloadResult> {
        interface ApiRecord {
          readonly api: unknown;
          readonly isRevoked: boolean;
        }

        interface ObsidianLibWrapper {
          readonly __obsidianLib: ObsidianLibState;
        }

        interface ObsidianLibState {
          readonly pluginApiRegistry?: RegistryWrapper;
        }

        interface RegistryWrapper {
          readonly value?: RegistryValue;
        }

        interface RegistryValue {
          readonly records?: Record<string, ApiRecord[]>;
        }

        function hasLiveApi(): boolean {
          const registryState = (window as Partial<ObsidianLibWrapper>).__obsidianLib;
          return registryState?.pluginApiRegistry?.value?.records?.[pluginId]?.some((candidate) => !candidate.isRevoked) ?? false;
        }

        async function checkIsApiPublished(): Promise<boolean> {
          try {
            await waitUntil({
              message: 'the plugin API was not published again after the reload',
              predicate: hasLiveApi,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
            return true;
          } catch {
            return false;
          }
        }

        const plainReloads: boolean[] = [];
        const cutShortReloads: boolean[] = [];

        try {
          for (let reloadIndex = 0; reloadIndex < reloadCount; reloadIndex++) {
            await app.plugins.disablePlugin(pluginId);
            await app.plugins.enablePlugin(pluginId);
            plainReloads.push(await checkIsApiPublished());
          }

          for (let reloadIndex = 0; reloadIndex < reloadCount; reloadIndex++) {
            await app.plugins.disablePlugin(pluginId);
            // Not awaited: Obsidian stores the new instance before it awaits the instance's load, so the disable below
            // can land while that load is still in progress, as an update or Hot Reload right after a load does.
            const enablePromise = app.plugins.enablePlugin(pluginId);
            await waitUntil({
              message: 'Obsidian never stored the new plugin instance',
              predicate: () => app.plugins.getPlugin(pluginId) !== null,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
            await app.plugins.disablePlugin(pluginId);
            await enablePromise;
            await app.plugins.enablePlugin(pluginId);
            cutShortReloads.push(await checkIsApiPublished());
          }
        } finally {
          // Every later suite shares this instance, so a live plugin is restored.
          if (app.plugins.getPlugin(pluginId) === null) {
            await app.plugins.enablePlugin(pluginId);
          }
        }

        return { cutShortReloads, plainReloads };
      },
      input: {
        pluginId: PLUGIN_ID,
        reloadCount: RELOAD_COUNT,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      }
    });

    expect(result.plainReloads).toEqual(Array.from({ length: RELOAD_COUNT }, () => true));
    expect(result.cutShortReloads).toEqual(Array.from({ length: RELOAD_COUNT }, () => true));
  });
});
