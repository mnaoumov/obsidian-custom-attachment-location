/**
 * @file
 *
 * Seeds this plugin's own `data.json` into an integration vault, set to the plugin's pattern rather than
 * Obsidian's attachment location.
 *
 * Since 13.0.0 a fresh install follows Obsidian's *Default location for new attachments*, and
 * `attachmentFolderPath` is not consulted at all until that mode is switched off. Nearly every suite is about
 * what the pattern does, and was written while the pattern was the default, so a vault with no `data.json`
 * would quietly turn those suites into tests of Obsidian's own setting. Seeding the mode off keeps each suite
 * meaning what it meant. The follow-Obsidian suite switches the mode on itself, as a user would.
 *
 * One key and nothing else: the plugin fills in every other setting from its defaults and writes the full
 * record back on load.
 */

import type { PopulateFilesParams } from 'obsidian-integration-testing';

// This plugin's `manifest.id`, which is also the folder it is installed into.
const PLUGIN_ID = 'obsidian-custom-attachment-location';

// Every vault the harness opens keeps its configuration in the default folder.
const VAULT_CONFIG_FOLDER = '.obsidian';

const SEEDED_SETTINGS = {
  shouldFollowObsidianAttachmentLocation: false
};

/**
 * Builds the file that puts this plugin in pattern mode.
 *
 * @returns The populate map.
 */
export function getPluginSettingsPopulate(): PopulateFilesParams {
  return {
    [`${VAULT_CONFIG_FOLDER}/plugins/${PLUGIN_ID}/data.json`]: JSON.stringify(SEEDED_SETTINGS)
  };
}
