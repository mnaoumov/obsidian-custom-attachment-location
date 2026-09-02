/**
 * @file
 *
 * Publishes which folders the user has designated as attachment units, and reads that answer back.
 *
 * The designation is this plugin's setting, but it is not only this plugin's business. Advanced Rename
 * and Delete Handler owns the delete interception from 12.0.0, and it has to keep a designated folder
 * whole when it rescues an attachment out of a deleted note's area (issue #70) — while deliberately
 * resolving attachment policy without knowing which plugin supplies it.
 *
 * So the designation rides the seam that already carries exactly that kind of answer: the `extended`
 * member this plugin hangs off the patched `Vault.getAvailablePathForAttachments`. A missing member
 * means no attachment-location plugin published one, which is the same "nobody owns this policy"
 * answer `extended` itself gives.
 *
 * Reading it back here rather than consulting the settings directly is the point: the collecting
 * commands and the other plugin then decide from ONE published answer. Two plugins deciding separately
 * what a single attachment is would leave a folder kept whole by one and torn apart by the other,
 * which is the failure `obsidian-dev-utils`' own attachment-unit-folder module exists to prevent.
 */

import type { Vault } from 'obsidian';

/**
 * The attachment-unit-folder designation published on {@link Vault.getAvailablePathForAttachments}.
 *
 * TODO(T898-P4): drop this local declaration once T897-P1 declares `checkIsAttachmentUnitFolder` on
 * `GetAvailablePathForAttachmentsFunctionExtended` in `obsidian-dev-utils` and this plugin consumes
 * that release.
 */
export interface AttachmentUnitFolderDesignation {
  /**
   * Whether a folder path is designated as an attachment unit.
   *
   * @param folderPath - The vault-relative path of the folder.
   * @returns `true` if the folder is designated as an attachment unit, `false` otherwise.
   */
  checkIsAttachmentUnitFolder?(this: void, folderPath: string): boolean;
}

/**
 * Parameters for {@link checkIsAttachmentUnitFolder}.
 */
export interface CheckIsAttachmentUnitFolderParams {
  /**
   * The vault-relative path of the folder.
   */
  readonly folderPath: string;

  /**
   * The vault whose patched `getAvailablePathForAttachments` carries the designation.
   */
  readonly vault: Vault;
}

/**
 * Reads the designation an attachment-location plugin published on the vault.
 *
 * @param params - The parameters for checking the folder.
 * @returns `true` if the folder is designated as an attachment unit, `false` when it is not and when
 * nobody published a designation at all.
 */
export function checkIsAttachmentUnitFolder(params: CheckIsAttachmentUnitFolderParams): boolean {
  /*
   * Reached through `Reflect.get` because naming the method reads it unbound, and the method itself is
   * not what is wanted here — only the designation hung off it.
   */
  const designation = Reflect.get(params.vault, 'getAvailablePathForAttachments') as Partial<AttachmentUnitFolderDesignation>;
  return designation.checkIsAttachmentUnitFolder?.(params.folderPath) ?? false;
}
