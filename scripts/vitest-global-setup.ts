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

import { VITEST_GLOBAL_SETUP_OPTIONS } from './helpers/vitest-global-setup-options.ts';

export const { setup, teardown } = createSetup(VITEST_GLOBAL_SETUP_OPTIONS);
