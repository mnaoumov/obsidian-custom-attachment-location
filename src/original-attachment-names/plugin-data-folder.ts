import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { getFileNameValidationMessage } from '@mnaoumov/obsidian-lib/validation';

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
