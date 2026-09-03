/**
 * @file
 *
 * Everything this plugin knows about Advanced Rename and Delete Handler, which owns rename/delete handling
 * since this plugin's 12.0.0.
 *
 * Three things need it, so it is written once: the suggestion banner that offers to install it, the
 * migration that hands this plugin's old rename/delete values over to it, and the read-back that asks it for
 * the values this plugin's own features still depend on.
 *
 * The API is DECLARED here rather than imported. That plugin is an Obsidian plugin repo, not an npm package,
 * so there is nothing to depend on — the shape below is this plugin's compiled-against copy of the contract,
 * and `watchPluginApi` negotiates the version at runtime.
 */

import type { PluginApiContract } from 'obsidian-dev-utils/obsidian/plugin/plugin-api';

import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/vault';

/**
 * Advanced Rename and Delete Handler's public API, as this plugin compiles against it.
 *
 * It publishes contract version `1.1.0`, so consumers ask for `^1`. The reads are SYNCHRONOUS by design:
 * this plugin calls them from `checkCallback(isChecking): boolean`, from settings-row `disabled` predicates,
 * and from loops over vault files — none of which can await.
 */
export interface AdvancedRenameAndDeleteHandlerApi {
  /**
   * The settings this plugin handed over and still reads.
   *
   * @returns The current values.
   */
  getSettings(): HandedOverSettings;

  /**
   * Whether a path is one the handler leaves alone entirely.
   *
   * Exposed as a predicate rather than as the raw include/exclude arrays deliberately: every plugin bundles
   * its OWN `obsidian-dev-utils`, so re-running those arrays through THIS plugin's copy of `PathSettings`
   * would let the two implementations drift apart across a library bump.
   *
   * @param path - The vault-relative path.
   * @returns Whether the path is ignored.
   */
  isPathIgnored(path: string): boolean;

  /**
   * Whether a file is an attachment even though its extension says otherwise — `.excalidraw.md` being the
   * canonical case. Same reasoning as {@link AdvancedRenameAndDeleteHandlerApi.isPathIgnored} for why this
   * crosses as a predicate.
   *
   * @param path - The vault-relative path.
   * @returns Whether the file is treated as an attachment.
   */
  isTreatedAsAttachment(path: string): boolean;

  /**
   * Offers the user a set of settings values this plugin proposes, and applies what they approve.
   *
   * Resolves only once the dialog is closed, so the caller learns whether the migration happened and can
   * set — or withhold — its own one-shot flag on that answer.
   *
   * @param params - The proposal.
   * @returns What the user approved.
   */
  migrateSettings(params: MigrateSettingsParams): Promise<MigrateSettingsResult>;
}

/**
 * The settings Advanced Rename and Delete Handler owns and this plugin reads back.
 */
export interface HandedOverSettings {
  /**
   * What to do with a folder a deletion or a move has left empty.
   */
  readonly emptyFolderBehavior: EmptyFolderBehavior;

  /**
   * Which referencing note owns an attachment several notes reference, highest priority first.
   */
  readonly notePriorities: readonly string[];

  /**
   * Whether renaming a note renames the attachment files that travel with it.
   */
  readonly shouldRenameAttachmentFiles: boolean;

  /**
   * Extensions whose files are attachments even though their extension says otherwise.
   */
  readonly treatAsAttachmentExtensions: readonly string[];
}

/**
 * The values a consumer may propose. Every member is optional: a consumer proposes only what it held.
 */
export interface MigratableSettings {
  readonly emptyFolderBehavior?: EmptyFolderBehavior;
  readonly excludePaths?: readonly string[];
  readonly includePaths?: readonly string[];
  readonly notePriorities?: readonly string[];
  readonly shouldHandleDeletions?: boolean;
  readonly shouldHandleRenames?: boolean;
  readonly shouldRenameAttachmentFiles?: boolean;
  readonly shouldRenameAttachmentFolder?: boolean;
  readonly shouldRescueSharedAttachments?: boolean;
  readonly treatAsAttachmentExtensions?: readonly string[];
}

/**
 * Parameters for {@link AdvancedRenameAndDeleteHandlerApi.migrateSettings}.
 */
export interface MigrateSettingsParams {
  /**
   * The values this plugin proposes.
   */
  readonly proposedSettings: MigratableSettings;

  /**
   * The `manifest.id` of the plugin making the proposal, so the dialog can say whose settings these are.
   */
  readonly sourcePluginId: string;
}

/**
 * The outcome of {@link AdvancedRenameAndDeleteHandlerApi.migrateSettings}.
 */
export interface MigrateSettingsResult {
  /**
   * Whether the user approved the migration. `false` means they cancelled and nothing was written — the
   * caller must NOT record the migration as done.
   */
  readonly isApplied: boolean;
}

export const ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID = 'advanced-rename-and-delete-handler';

export const ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME = 'Advanced Rename and Delete Handler';

/**
 * The contract version range this plugin compiled against.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE = '^1';

/**
 * What the MIGRATION needs — a single method, published since contract `1.0.0`.
 *
 * Supplied to `watchPluginApi` as the consumer's own contract, which wins over the provider's. The two
 * consumers here need different halves of the API and must be told apart: the migration works against
 * every `^1` provider, while the read-back below does not.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT: PluginApiContract = {
  migrateSettings: {}
};

/**
 * What the READ-BACK needs — the three members contract `1.1.0` added.
 *
 * This is load-bearing rather than decorative. Advanced Rename and Delete Handler `1.1.1` publishes
 * contract `1.0.0`, whose own contract declares only `migrateSettings` — so it satisfies `^1` and passes a
 * shape check made against the PROVIDER's contract. Without this one, a user on that released version would
 * be handed an API with no `getSettings` and every read would throw. With it, the record fails the shape
 * check, `PluginApiRef.value` stays `null`, and this plugin falls back to
 * {@link DEFAULT_HANDED_OVER_SETTINGS} until the provider is new enough.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_READ_BACK_API_CONTRACT: PluginApiContract = {
  getSettings: {},
  isPathIgnored: {},
  isTreatedAsAttachment: {}
};

/**
 * What this plugin uses while Advanced Rename and Delete Handler is not available — not installed, not
 * enabled, or not yet loaded.
 *
 * These are THIS plugin's own historic defaults rather than the other plugin's, deliberately: a user who
 * declines the suggestion keeps this plugin's behavior as it always was, instead of silently inheriting the
 * defaults of a plugin they chose not to install. `emptyFolderBehavior` is the visible case — this plugin
 * has always defaulted to {@link EmptyFolderBehavior.DeleteWithEmptyParents}, while the other plugin
 * defaults to {@link EmptyFolderBehavior.Keep}.
 *
 * A user who HAS the other plugin sees its values instead, which is the whole point of reading them back.
 * A user who does not keeps working defaults, and the values they configured before 12.0.0 are still held in
 * the pending proposal until a migration applies them.
 */
export const DEFAULT_HANDED_OVER_SETTINGS: HandedOverSettings = {
  emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
  notePriorities: [],
  shouldRenameAttachmentFiles: false,
  treatAsAttachmentExtensions: ['.excalidraw.md']
};
