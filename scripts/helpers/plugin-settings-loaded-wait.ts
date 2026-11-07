/**
 * @file
 *
 * Waits, from Node, until this plugin has set its settings component.
 *
 * On Android the harness enables this plugin before `Advanced Rename and Delete Handler`, and this plugin's
 * `onloadImpl` runs only once that dependency has published its API. So the first suite of a run can start while the
 * gate is still closed, and a closure that looks the settings up straight away finds nothing. The wait lives in Node,
 * through `pollInObsidian`, because a long wait inside an `evalInObsidian` closure would outlast the transport's cap.
 */

import { pollInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';

const PLUGIN_SETTINGS_LOADED_TIMEOUT_IN_MILLISECONDS = 60_000;

/**
 * Waits until this plugin's settings component is set.
 *
 * @returns A {@link Promise} that resolves once the settings component is there.
 */
export async function waitForPluginSettingsLoaded(): Promise<void> {
  await pollInObsidian({
    poll: ({ app }) => {
      const plugin = app.plugins.getPlugin('obsidian-custom-attachment-location');
      if (!plugin) {
        return false;
      }
      try {
        const component: unknown = Reflect.get(plugin, 'pluginSettingsComponent');
        return typeof component === 'object' && component !== null;
      } catch {
        // The accessor throws until the plugin has set its component.
        return false;
      }
    },
    timeoutInMilliseconds: PLUGIN_SETTINGS_LOADED_TIMEOUT_IN_MILLISECONDS,
    timeoutMessage: 'The plugin settings component was never set: the dependency gate did not open',
    until: (isLoaded) => isLoaded,
    vaultPath: getTemporaryVault().path
  });
}
