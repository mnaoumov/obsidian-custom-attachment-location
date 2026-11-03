import { createSetup } from 'obsidian-integration-testing/vitest-global-setup-plugin';

import { VITEST_GLOBAL_SETUP_OPTIONS } from './helpers/vitest-global-setup-options.ts';

/**
 * Runs the same seeded vault with the plugin enabled after the workspace layout is ready.
 */
export const { setup, teardown } = createSetup({
  ...VITEST_GLOBAL_SETUP_OPTIONS,
  pluginEnableTiming: 'after-layout-ready'
});
