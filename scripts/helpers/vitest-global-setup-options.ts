import type { CreateSetupOptions } from 'obsidian-integration-testing/vitest-global-setup-plugin';

import {
  ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
  getAdvancedRenameAndDeleteHandlerPopulate
} from './advanced-rename-and-delete-handler-seed.ts';
import { getPluginSettingsPopulate } from './plugin-settings-seed.ts';

/**
 * The dependency and pattern-mode seeds shared by both desktop timings and Android.
 */
export const VITEST_GLOBAL_SETUP_OPTIONS: CreateSetupOptions = {
  enableCommunityPlugins: [ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID],
  populate: async () => ({
    ...await getAdvancedRenameAndDeleteHandlerPopulate(),
    ...getPluginSettingsPopulate()
  })
};
