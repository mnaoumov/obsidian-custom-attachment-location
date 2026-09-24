import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * The dependency on Advanced Rename and Delete Handler, driven end to end: take it away and this plugin's
 * feature surface goes with it; bring it back and the surface returns, with no restart.
 *
 * The collect command stands in for the whole surface — it is registered by `onloadImpl`, which is exactly
 * what the dependency gate withholds. Bringing it back also re-runs `onloadImpl` on a plugin instance that
 * has run it before, which is the path a plugin written for a single load has to survive.
 *
 * The dependency is put back in a `finally`: every later file in the run relies on it being there.
 *
 * Cross-platform: the manifest declares `isDesktopOnly: false`, and the gate behaves the same on a phone.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const DEPENDENCY_PLUGIN_ID = 'advanced-rename-and-delete-handler';
const COLLECT_COMMAND_ID = `${PLUGIN_ID}:collect-attachments-entire-vault`;
/*
 * Under the transport's ~30s per-closure cap, not at it — and on Android that cap is not raised at all. The one
 * closure below charges this ceiling TWICE, once for the withdrawal and once for the return, and the whole
 * callback is a single evaluation, so the sum is what has to fit, leaving room for the two plugin toggles
 * themselves. Both waits are for an event the dependency gate fires as soon as the plugin list changes; the
 * ceiling is headroom for a loaded machine, not a budget for slow work.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 10_000;

interface DependencyProbeResult {
  readonly isCommandRegisteredAfterReturn: boolean;
  readonly isCommandRegisteredBefore: boolean;
  readonly isCommandRegisteredWhileMissing: boolean;
}

describe('Advanced Rename and Delete Handler as a dependency', () => {
  it('withholds this plugin\'s commands while it is disabled, and restores them when it comes back', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        collectCommandId,
        dependencyPluginId,
        lib: { waitUntil },
        timeoutInMilliseconds
      }): Promise<DependencyProbeResult> {
        function isCommandRegistered(): boolean {
          return Object.hasOwn(app.commands.commands, collectCommandId);
        }

        const isCommandRegisteredBefore = isCommandRegistered();

        try {
          await app.plugins.disablePlugin(dependencyPluginId);
          await waitUntil({
            message: 'this plugin withdraws its commands once the dependency is gone',
            predicate: () => !isCommandRegistered(),
            timeoutInMilliseconds
          });
          const isCommandRegisteredWhileMissing = isCommandRegistered();

          await app.plugins.enablePlugin(dependencyPluginId);
          await waitUntil({
            message: 'this plugin registers its commands again once the dependency is back',
            predicate: isCommandRegistered,
            timeoutInMilliseconds
          });

          return {
            isCommandRegisteredAfterReturn: isCommandRegistered(),
            isCommandRegisteredBefore,
            isCommandRegisteredWhileMissing
          };
        } finally {
          if (!app.plugins.enabledPlugins.has(dependencyPluginId)) {
            await app.plugins.enablePlugin(dependencyPluginId);
          }
        }
      },
      input: {
        collectCommandId: COLLECT_COMMAND_ID,
        dependencyPluginId: DEPENDENCY_PLUGIN_ID,
        timeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      }
    });

    expect(result.isCommandRegisteredBefore).toBe(true);
    expect(result.isCommandRegisteredWhileMissing).toBe(false);
    expect(result.isCommandRegisteredAfterReturn).toBe(true);
  });
});
