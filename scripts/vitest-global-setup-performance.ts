import { createSetup } from 'obsidian-integration-testing/vitest-global-setup-plugin';

import {
  ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
  getAdvancedRenameAndDeleteHandlerPopulate
} from './helpers/advanced-rename-and-delete-handler-seed.ts';
import { generatePerformanceVault } from './helpers/generate-performance-vault.ts';
import { getPluginSettingsPopulate } from './helpers/plugin-settings-seed.ts';

/**
 * Vitest global setup for the `integration-tests:desktop-performance` project: it
 * pre-populates the vault with many notes embedding binary attachments via
 * `TemporaryVault.populate()` before Obsidian opens it, so the startup scan indexes
 * everything in one pass.
 *
 * Advanced Rename and Delete Handler is seeded alongside, as in every other project:
 * this plugin declares it as a dependency and loads nothing without it.
 */
export const { setup, teardown } = createSetup({
  enableCommunityPlugins: [ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID],
  populate: async () => ({
    ...generatePerformanceVault(),
    ...await getAdvancedRenameAndDeleteHandlerPopulate(),
    ...getPluginSettingsPopulate()
  })
});
