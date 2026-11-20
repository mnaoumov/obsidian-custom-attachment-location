import type { App } from 'obsidian';

/**
 * Whether a folder exists, asking the vault's in-memory index before the disk.
 *
 * `vault.exists` is a filesystem round trip, and saving an attachment used to make two of them for the same folder:
 * one in `AttachmentPathManager` and one in the `createBinary` patch. On a large vault, with the watcher and other
 * plugins busy on the same thread pool, each one could queue for tens to hundreds of milliseconds, and a batch of N
 * files paid that 2N times while the user watched the links arrive one by one. A folder the index knows exists, so
 * only a folder it does not know (a new one, or a hidden one the index never lists) goes to the disk.
 *
 * @param app - The app.
 * @param folderPath - The folder's vault path.
 * @returns `true` when the folder exists.
 */
export async function doesFolderExist(app: App, folderPath: string): Promise<boolean> {
  return app.vault.getFolderByPath(folderPath) !== null || await app.vault.exists(folderPath);
}
