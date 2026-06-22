import { createSetup } from 'obsidian-integration-testing/vitest-global-setup';

import { generatePerformanceVault } from './helpers/generate-performance-vault.ts';

/**
 * Vitest global setup for the `integration-tests:desktop-performance` project: it
 * pre-populates the vault with many notes embedding binary attachments via
 * `TempVault.populate()` before Obsidian opens it, so the startup scan indexes
 * everything in one pass.
 */
export const { setup, teardown } = createSetup({ populate: generatePerformanceVault });
