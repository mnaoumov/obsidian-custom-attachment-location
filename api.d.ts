/**
 * @file
 *
 * This plugin's whole public surface, as a consumer sees it.
 *
 * Hand-written and self-contained on purpose: it imports from `obsidian` and nothing else, so a plugin that
 * has never heard of `obsidian-dev-utils` can copy this file, or reference it where it sits, and depend on
 * this plugin with no build-time dependency on this repository at all.
 *
 * {@link CustomAttachmentLocationApi} is published through the `obsidian-dev-utils` plugin registry under the
 * plugin id `obsidian-custom-attachment-location`, so a consumer gets version negotiation, a handle that is
 * revoked when this plugin unloads, and a wait that ends when this plugin loads rather than a lookup that
 * returns `undefined` because it ran first.
 *
 * ## Why this exists rather than `vault.getConfig('attachmentFolderPath')`
 *
 * This plugin patches `Vault.getConfig('attachmentFolderPath')`, which looks like the seam you want and is
 * not one. That patch answers with this plugin's value only while a note is OPEN, and the value it answers
 * with is **the open note's**, computed once when the file was opened. A consumer looping over every note in
 * the vault therefore gets the active note's attachment folder for all of them — silently, with no error, and
 * indistinguishable from a correct answer. The patch is a write-path override for Obsidian's own attachment
 * creation, not a readable configuration. Ask {@link CustomAttachmentLocationApi.getAttachmentFolderPath}
 * instead, once per note.
 */

import type {
  TAbstractFile,
  TFile
} from 'obsidian';

/**
 * This plugin's API, published through the `obsidian-dev-utils` plugin registry under the plugin id
 * `obsidian-custom-attachment-location`.
 *
 * Every member is asynchronous, and that is not an accident of the implementation: an attachment folder is
 * the result of evaluating a user-written template whose tokens can read the note's frontmatter, the
 * attachment's bytes and its file stats. There is no synchronous answer to hand back, so a caller that cannot
 * `await` — a `checkCallback`, a settings row's `disabled` predicate — cannot use this API and should not
 * pretend it can.
 *
 * ## Non-interactive
 *
 * Both reads run in a context that never asks the user anything — unlike
 * {@link CustomAttachmentLocationApi.collectAttachments} and {@link CustomAttachmentLocationApi.migrateSettings},
 * which act and may ask. A folder or file-name template may hold a
 * `${prompt}` token, and an audit walking a vault must not raise one dialog per note. In that context the
 * token resolves to Obsidian's own placeholder path segment instead of opening a dialog, so a template that
 * genuinely needs the user produces an answer carrying that placeholder rather than a hang. A consumer that
 * cares can spot it; a consumer that does not is still not blocked.
 *
 * ## While the dependency is missing
 *
 * This plugin is gated on Advanced Rename and Delete Handler being installed and enabled, and registers
 * nothing at all while it is not. The registry handle is revoked with that surface, so a consumer holding one
 * sees the API GO AWAY rather than answering from torn-down components — the same observation as this plugin
 * being uninstalled, which for a consumer is the same thing to do about it.
 */
export interface CustomAttachmentLocationApi {
  /**
   * Collects the attachments of the given notes, or of every note under the given folders, into the folders
   * the settings say they belong in — exactly as the `Collect attachments` commands do.
   *
   * The commands act on the ACTIVE file, so without this a plugin wanting one particular note collected would
   * have to open it first: a visible side effect of an unrelated operation.
   *
   * This is an action, not a read, and it behaves as the command does, dialogs included: several files or a
   * folder are confirmed with the user first, a note this plugin leaves alone is refused with a notice, an
   * attachment several notes share follows `collectAttachmentUsedByMultipleNotesMode` (which may be
   * `Prompt`), and a template's `${prompt}` token asks. Do not call it from an audit that must stay silent.
   *
   * Added in contract version `1.2.0`.
   *
   * @param params - What to collect.
   * @returns A promise that settles once the collect has finished — queued behind any collect already
   *   running, so it is safe to call right after an operation of your own that moved or wrote the notes. A
   *   caller that does not need to sequence on it need not await it.
   */
  collectAttachments(params: CollectAttachmentsParams): Promise<void>;

  /**
   * The folder this plugin would put a NEW attachment of `notePath`'s in.
   *
   * The per-note read this plugin has otherwise had no way to answer. Asked once per note, it is what an
   * audit — "does this attachment sit where its note's settings say it should?" — needs, and what
   * `vault.getConfig('attachmentFolderPath')` cannot give: see this file's header.
   *
   * Answers about the destination for a NEWLY SAVED attachment, the `Location for new attachments` setting.
   * **Collecting has a destination of its own** when the user has given it one, and this call deliberately
   * does not answer about that; a member for it can be added without breaking this one.
   *
   * @param params - The note, and optionally the attachment whose name the template may read.
   * @returns The folder path from the vault root, with no trailing slash — or `null` when this plugin leaves
   *   `notePath` alone entirely, per the include and exclude lists it reads from Advanced Rename and Delete
   *   Handler. `null` is the signal to fall back to Obsidian's own `attachmentFolderPath`: it means this
   *   plugin is installed and has decided not to manage this note, which is a different answer from "this
   *   plugin is not installed" and is meant to be.
   */
  getAttachmentFolderPath(params: GetAttachmentFolderPathParams): Promise<null | string>;

  /**
   * Where an attachment a note already references BELONGS — the full path, folder and file name both.
   *
   * The acting half of the same question {@link CustomAttachmentLocationApi.getAttachmentFolderPath} answers
   * for reading: a consumer that has found a misplaced attachment and wants to move it needs the destination
   * path, not just the folder, because the file name is templated too.
   *
   * The reference and the sequence number this needs are resolved here, from the note's backlinks and from
   * this plugin's own per-note numbering, so a caller supplies two paths and nothing else. That matters for
   * `${sequenceNumber}`: which attachment of the note this is is a property of the note's link order, and a
   * caller re-deriving it would be re-implementing this plugin.
   *
   * @param params - The note, and the attachment it references.
   * @returns The path the attachment belongs at, from the vault root — or `null` when it is already there,
   *   when `notePath` is left alone entirely, or when `attachmentPathOrFile` names no file or is not
   *   referenced by that note. `null` therefore means "nothing to do", in every one of its senses.
   */
  getProperAttachmentPath(params: GetProperAttachmentPathParams): Promise<null | string>;

  /**
   * Offers the user settings another plugin used to own, and applies what they approve.
   *
   * The one member that DOES ask the user something. This plugin owns the settings, so it owns the dialog: it
   * puts each proposed value next to the one it holds now, and the user approves, edits or declines each row.
   * The proposing plugin never writes into this plugin's `data.json`.
   *
   * Only the settings that would actually change are shown. A proposal that changes nothing opens no dialog
   * and answers `isApplied: true`, since there is nothing left to hand over. Two proposals arriving at once
   * are asked one after the other, never as two dialogs stacked on top of each other.
   *
   * Added in contract version `1.1.0`. Its shape matches `obsidian-dev-utils`' `SettingsMigrationApi`, so a
   * consumer that has that library can hand the whole offer to its `SettingsMigrationComponent`.
   *
   * @param params - The proposal.
   * @returns Whether the user approved it. `false` means nothing was written.
   */
  migrateSettings(params: MigrateSettingsParams): Promise<MigrateSettingsResult>;
}

/**
 * Parameters for {@link CustomAttachmentLocationApi.collectAttachments}.
 */
export interface CollectAttachmentsParams {
  /**
   * The notes to collect for, and folders whose notes are all collected for — each as a vault-relative path
   * or as the file or folder itself. An entry naming nothing in the vault is skipped, so a list that names
   * nothing collects nothing.
   */
  readonly pathsOrFiles: readonly (string | TAbstractFile)[];
}

/**
 * What `Collect attachments` does with an attachment several notes reference. The same spellings the
 * settings file stores.
 */
export type CollectAttachmentUsedByMultipleNotesMode = 'Cancel' | 'Copy' | 'Move' | 'Prompt' | 'Skip';

/**
 * Parameters for {@link CustomAttachmentLocationApi.getAttachmentFolderPath}.
 */
export interface GetAttachmentFolderPathParams {
  /**
   * The name of the attachment the folder is being asked about, extension included.
   *
   * Optional, and worth supplying whenever it is known: a folder template may read the attachment's name
   * through `${originalAttachmentFileName}` or the tokens derived from it, so two attachments of the same
   * note can legitimately belong in different folders. Left out, the folder is computed against Obsidian's
   * own placeholder name, which is what this plugin itself does when it has no attachment in hand.
   */
  readonly attachmentFileName?: string | undefined;

  /**
   * The note whose attachment folder is being asked about, as a vault-relative path.
   */
  readonly notePath: string;
}

/**
 * The settings another plugin may propose through {@link CustomAttachmentLocationApi.migrateSettings}: the ones
 * that go with collecting attachments.
 *
 * Every member is optional, so a plugin proposes only what it actually held, and a value this plugin already
 * has is never overwritten by a default nobody chose.
 */
export interface MigratableCollectSettings {
  /**
   * Folders whose whole hierarchy travels as one attachment. Entries use the same path-or-regular-expression
   * syntax as the settings tab.
   */
  readonly attachmentUnitFolderPaths?: readonly string[];

  /**
   * What `Collect attachments` does with an attachment several notes reference.
   */
  readonly collectAttachmentUsedByMultipleNotesMode?: CollectAttachmentUsedByMultipleNotesMode;

  /**
   * Paths whose attachments `Collect attachments` leaves where they are.
   */
  readonly excludePathsFromAttachmentCollecting?: readonly string[];

  /**
   * What `Move attachment to proper folder` does with an attachment several notes reference.
   */
  readonly moveAttachmentToProperFolderUsedByMultipleNotesMode?: MoveAttachmentToProperFolderUsedByMultipleNotesMode;

  /**
   * Whether a note's attachments are collected each time the note changes.
   */
  readonly shouldCollectAttachmentsAutomatically?: boolean;
}

/**
 * Parameters for {@link CustomAttachmentLocationApi.migrateSettings}.
 */
export interface MigrateSettingsParams {
  /**
   * The values the calling plugin proposes.
   */
  readonly proposedSettings: MigratableCollectSettings;

  /**
   * The `manifest.id` of the plugin making the proposal. The dialog names that plugin, so the user knows whose
   * settings they are being offered.
   */
  readonly sourcePluginId: string;
}

/**
 * The outcome of {@link CustomAttachmentLocationApi.migrateSettings}.
 */
export interface MigrateSettingsResult {
  /**
   * Whether the user approved the migration. `false` means they cancelled and nothing was written, so the
   * caller must keep its proposal pending rather than record the handover as done.
   */
  readonly isApplied: boolean;
}

/**
 * What `Move attachment to proper folder` does with an attachment several notes reference. The same spellings
 * the settings file stores.
 */
export type MoveAttachmentToProperFolderUsedByMultipleNotesMode = 'Cancel' | 'CopyAll' | 'Prompt' | 'Skip';

/**
 * Parameters for {@link CustomAttachmentLocationApi.getProperAttachmentPath}.
 */
export interface GetProperAttachmentPathParams {
  /**
   * The attachment, as a vault-relative path or as the file itself.
   *
   * It must be referenced by `notePath`: this call answers where THAT note's copy of it belongs, and an
   * attachment several notes share has as many proper paths as it has referencing notes.
   */
  readonly attachmentPathOrFile: string | TFile;

  /**
   * The note that references the attachment, as a vault-relative path.
   */
  readonly notePath: string;
}
