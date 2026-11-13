import type { DataAdapter } from 'obsidian';

import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { getFileNameValidationMessage } from '@mnaoumov/obsidian-lib/validation';

/**
 * The plugin's own subfolder inside a plugin data folder. Everything under it belongs to the plugin.
 */
export const PLUGIN_DATA_SUBFOLDER_NAME = 'obsidian-custom-attachment-location';

/**
 * The name of the explanation file the plugin writes beside its data.
 */
export const PLUGIN_DATA_FOLDER_README_FILE_NAME = 'README.md';

/**
 * The first line of every explanation file the plugin writes. A `README.md` that does not open with it is the user's,
 * and the plugin never writes over it.
 */
export const PLUGIN_DATA_FOLDER_README_HEADING = '# Plugin sync data - do not remove';

/**
 * Tells whether a `README.md` is one the plugin wrote.
 *
 * @param text - The file's text.
 * @returns Whether it opens with the plugin's heading.
 */
export function isPluginDataFolderReadme(text: string): boolean {
  return text.startsWith(PLUGIN_DATA_FOLDER_README_HEADING);
}

/**
 * Tells whether a plugin data folder belongs to the plugin as a whole, so it may be excluded and explained as one.
 *
 * It does when it does not exist yet (the plugin creates it), or when it holds nothing but the plugin's own subfolder
 * and the plugin's own `README.md`. Hidden entries such as `.DS_Store` are ignored. Any other content makes it a
 * folder the user keeps their own files in, which the plugin must leave alone.
 *
 * @param adapter - The vault's data adapter.
 * @param folder - Vault-relative folder.
 * @returns Whether the plugin owns the whole folder.
 */
export async function isPluginOwnedDataFolder(adapter: DataAdapter, folder: string): Promise<boolean> {
  if (!await adapter.exists(folder)) {
    return true;
  }
  const listed = await adapter.list(folder);
  if (listed.folders.some((child) => isVisiblePath(child) && child !== `${folder}/${PLUGIN_DATA_SUBFOLDER_NAME}`)) {
    return false;
  }
  for (const file of listed.files) {
    if (!isVisiblePath(file)) {
      continue;
    }
    if (file !== `${folder}/${PLUGIN_DATA_FOLDER_README_FILE_NAME}` || !isPluginDataFolderReadme(await adapter.read(file))) {
      return false;
    }
  }
  return true;
}

function isVisiblePath(path: string): boolean {
  return !path.slice(path.lastIndexOf('/') + 1).startsWith('.');
}

/**
 * The folder that holds the synchronized plugin data of a fresh install.
 */
export const DEFAULT_PLUGIN_DATA_FOLDER = '@Plugin sync data (DO NOT REMOVE)';

/**
 * The folder every earlier version used. An install or vault that already has history there keeps it as its
 * discovery anchor for good.
 */
export const LEGACY_PLUGIN_DATA_FOLDER = 'Plugin data';

/**
 * Validates the static store parent before it reaches the adapter. Tokens are never evaluated here.
 *
 * @param folder - Vault-relative folder.
 * @param areHiddenFoldersAllowed - Explicit permission to use hidden segments.
 * @returns A validation error, or `null` for a contained path.
 */
export function validatePluginDataFolder(folder: string, areHiddenFoldersAllowed: boolean): null | string {
  const segments = folder.split('/');
  if (segments.some((segment) => !segment || segment === '.' || segment === '..' || segment.trim() !== segment || /[{}]/.test(segment) || getFileNameValidationMessage(segment, true) !== '')) {
    return t(($) => $.originalAttachmentNames.storage.invalidFolder);
  }
  return !areHiddenFoldersAllowed && segments.some((segment) => segment.startsWith('.')) ? t(($) => $.originalAttachmentNames.storage.hiddenFolderPermission) : null;
}
