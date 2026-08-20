/**
 * @file
 *
 * Resolves which folder an attachment belongs to when the user has designated folders that must
 * travel as a single unit.
 *
 * Some formats are really a directory tree rather than a file: a saved `.html` page next to its
 * `_files/` directory, an `.excalidraw` next to the images it references. Collecting only the linked
 * file leaves the rest behind and the attachment arrives broken.
 */

import { dirname } from 'obsidian-dev-utils/path';

/**
 * Parameters for {@link findAttachmentUnitFolderPath}.
 */
export interface FindAttachmentUnitFolderPathParams {
  /**
   * The vault-relative path of the attachment.
   */
  readonly attachmentPath: string;

  /**
   * Whether a folder path is designated as an attachment unit.
   */
  checkIsAttachmentUnitFolder(folderPath: string): boolean;
}

/**
 * Parameters for {@link rebasePathOntoFolder}.
 */
export interface RebasePathOntoFolderParams {
  /**
   * The folder's new path.
   */
  readonly newFolderPath: string;

  /**
   * The folder's old path.
   */
  readonly oldFolderPath: string;

  /**
   * The path to rebase.
   */
  readonly path: string;
}

/**
 * Finds the folder that an attachment must travel with.
 *
 * Returns the **outermost** designated ancestor, not the nearest one. With nested designations,
 * moving the nearest would tear the outer tree in half, which is the failure the whole feature
 * exists to prevent.
 *
 * The vault root is never a unit, however the patterns are written: designating it would make every
 * collection a no-op at best and a vault-wide move at worst.
 *
 * @param params - The parameters.
 * @returns The unit folder's path, or `null` when the attachment belongs to no unit.
 */
export function findAttachmentUnitFolderPath(params: FindAttachmentUnitFolderPathParams): null | string {
  const parentFolderPath = dirname(params.attachmentPath);
  if (!parentFolderPath || parentFolderPath === '.' || parentFolderPath === '/') {
    return null;
  }

  const segments = parentFolderPath.split('/').filter(Boolean);
  for (let count = 1; count <= segments.length; count++) {
    const candidate = segments.slice(0, count).join('/');
    if (params.checkIsAttachmentUnitFolder(candidate)) {
      return candidate;
    }
  }

  return null;
}

/**
 * Rebases a path from one folder onto another.
 *
 * Used to work out where a linked attachment ends up once its whole unit folder has moved, so the
 * link can be pointed at the file's new home rather than at where the folder used to be.
 *
 * @param params - The parameters.
 * @returns The rebased path, or `null` when the path does not sit inside the old folder.
 */
export function rebasePathOntoFolder(params: RebasePathOntoFolderParams): null | string {
  const prefix = `${params.oldFolderPath}/`;
  if (!params.path.startsWith(prefix)) {
    return null;
  }

  return `${params.newFolderPath}/${params.path.slice(prefix.length)}`;
}
