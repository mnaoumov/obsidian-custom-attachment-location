/**
 * @file
 *
 * Seeds Advanced Rename and Delete Handler into an integration vault, because this plugin declares it as a
 * dependency and loads nothing of its own until it is there.
 *
 * Without it every suite would meet this plugin blocked — no commands, no patches, no settings — and fail on
 * something that has nothing to do with what it tests. So every project that opens a vault seeds it: the plain
 * desktop and Android projects through `scripts/vitest-global-setup.ts`, and the demo-vault and performance
 * projects through their own setups.
 *
 * The seeded copy is the RELEASED build, pinned, for the reason `download-released-plugin.ts` gives: it is
 * what a user installs, and a test that follows a moving artifact stops being a statement about anything.
 *
 * Its settings are seeded too, so that it does nothing a suite did not ask for. Renames, attachment-folder
 * moves and deletions stay off, which is what the vault looked like to this plugin's suites before the
 * dependency existed. The values this plugin reads back — what to do with an emptied folder, which extensions
 * are attachments, which notes win a tie — are this plugin's own historic defaults, the ones it used while the
 * other plugin was absent, so a suite written against those keeps meaning what it meant.
 */

import type { PopulateFilesParams } from 'obsidian-integration-testing';

import { downloadReleasedPlugin } from './download-released-plugin.ts';

/**
 * The dependency's `manifest.id`, which is also the folder it is seeded into.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID = 'advanced-rename-and-delete-handler';

/**
 * The release seeded. `1.3.0` publishes contract `1.1.0`, the lowest the dependency accepts.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_VERSION = '1.3.0';

const ADVANCED_RENAME_AND_DELETE_HANDLER_REPO = 'mnaoumov/obsidian-advanced-rename-and-delete-handler';

// Every vault the harness opens keeps its configuration in the default folder.
const VAULT_CONFIG_FOLDER = '.obsidian';

/**
 * The settings seeded with it. Exported so a suite that owns its vault outright (the store-screenshot captures)
 * can write the same record with renames switched on.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_SEEDED_SETTINGS = {
  emptyFolderBehavior: 'DeleteWithEmptyParents',
  notePriorities: [],
  shouldHandleDeletions: false,
  shouldHandleRenames: false,
  shouldRenameAttachmentFiles: false,
  shouldRenameAttachmentFolder: false,
  treatAsAttachmentExtensions: ['.excalidraw.md']
};

/**
 * Builds the files that install the dependency into a vault, with its settings.
 *
 * @returns The populate map.
 */
export async function getAdvancedRenameAndDeleteHandlerPopulate(): Promise<PopulateFilesParams> {
  const files = await downloadReleasedPlugin({
    pluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
    repo: ADVANCED_RENAME_AND_DELETE_HANDLER_REPO,
    version: ADVANCED_RENAME_AND_DELETE_HANDLER_VERSION
  });

  const pluginFolder = `${VAULT_CONFIG_FOLDER}/plugins/${ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID}`;
  return {
    [`${pluginFolder}/data.json`]: JSON.stringify(ADVANCED_RENAME_AND_DELETE_HANDLER_SEEDED_SETTINGS),
    [`${pluginFolder}/main.js`]: files.mainJs,
    [`${pluginFolder}/manifest.json`]: files.manifestJson
  };
}
