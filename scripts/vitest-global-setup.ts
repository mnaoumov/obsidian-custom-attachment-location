/**
 * @file
 *
 * The global setup of the desktop and Android projects: `obsidian-integration-testing`'s own, plus Advanced
 * Rename and Delete Handler, which this plugin declares as a dependency and cannot load without, and this
 * plugin's own settings, set to its pattern rather than to Obsidian's attachment location (see
 * `helpers/plugin-settings-seed.ts`).
 *
 * The dependency is enabled after this plugin, so every run also drives the live path: this plugin loads
 * blocked, and finishes loading the moment its dependency's API appears.
 */

import { createSetup } from 'obsidian-integration-testing/vitest-global-setup-plugin';

import {
  ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
  getAdvancedRenameAndDeleteHandlerPopulate
} from './helpers/advanced-rename-and-delete-handler-seed.ts';
import { getPluginSettingsPopulate } from './helpers/plugin-settings-seed.ts';

export const { setup, teardown } = createSetup({
  enableCommunityPlugins: [ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID],
  populate: async () => ({
    ...await getAdvancedRenameAndDeleteHandlerPopulate(),
    ...getPluginSettingsPopulate()
  })
});
