/**
 * @file
 *
 * Everything this plugin knows about `Advanced Rename and Delete Handler`, which owns rename/delete handling
 * since this plugin's 12.0.0.
 *
 * Three things need it, so it is written once: the suggestion banner that offers to install it, the
 * migration that hands this plugin's old rename/delete values over to it, and the read-back that asks it for
 * the values this plugin's own features still depend on.
 *
 * The API is DECLARED here rather than imported. That plugin is an Obsidian plugin repo, not an npm package,
 * so there is nothing to depend on — the shape below is this plugin's compiled-against copy of the API,
 * and `watchPluginApi` negotiates the version at runtime.
 *
 * The CONTRACTS are the provider's own. Its copyable `api.d.ts` and `api-contract.ts` are copied VERBATIM into
 * `./api/`, and each contract below takes its entries, schemas included.
 * Refresh the copy from the provider's repository rather than editing it, so both ends keep checking ONE
 * definition.
 */

import type { SettingsMigrationApi } from '@mnaoumov/obsidian-lib/plugin/settings-migration-api';
import type { ApiContract } from '@mnaoumov/typescript-lib/api-contract';

import { EmptyFolderBehavior } from '@mnaoumov/obsidian-lib/vault';

import type {
  AdvancedRenameAndDeleteHandlerApi as ProviderApi,
  EmptyFolderBehavior as ProviderEmptyFolderBehavior,
  HandedOverSettings as ProviderHandedOverSettings,
  MigratableSettings as ProviderMigratableSettings
} from './api/api.d.ts';

import { ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT } from './api/api-contract.ts';

/**
 * `Advanced Rename and Delete Handler`'s public API, as this plugin compiles against it.
 *
 * It publishes contract version `1.2.0` (`1.1.0` before its 2.3.0), so consumers ask for `^1`. The reads are SYNCHRONOUS by design:
 * this plugin calls them from `checkCallback(isChecking): boolean`, from settings-row `disabled` predicates,
 * and from loops over vault files — none of which can await.
 *
 * `migrateSettings` is inherited rather than re-declared: it is the generic handover envelope, and taking it
 * from `SettingsMigrationApi` is what gives both ends of that handover one declaration to compile against
 * instead of two copies that drift in silence. What stays declared here is what is genuinely this pair's
 * own — the read-back members below, and the {@link MigratableSettings} payload.
 */
export interface AdvancedRenameAndDeleteHandlerApi extends SettingsMigrationApi<MigratableSettings> {
  /**
   * The settings this plugin handed over and still reads.
   *
   * @returns The current values.
   */
  readonly getSettings: () => HandedOverSettings;

  /**
   * Whether a path is one the handler leaves alone entirely.
   *
   * Exposed as a predicate rather than as the raw include/exclude arrays deliberately: every plugin bundles
   * its OWN `@mnaoumov/obsidian-lib`, so re-running those arrays through THIS plugin's copy of `PathSettings`
   * would let the two implementations drift apart across a library bump.
   *
   * @param path - The vault-relative path.
   * @returns Whether the path is ignored.
   */
  readonly isPathIgnored: (path: string) => boolean;

  /**
   * Whether a file is an attachment even though its extension says otherwise — `.excalidraw.md` being the
   * canonical case. Same reasoning as {@link AdvancedRenameAndDeleteHandlerApi.isPathIgnored} for why this
   * crosses as a predicate.
   *
   * @param path - The vault-relative path.
   * @returns Whether the file is treated as an attachment.
   */
  readonly isTreatedAsAttachment: (path: string) => boolean;
}

/**
 * The settings `Advanced Rename and Delete Handler` owns and this plugin reads back.
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

export const ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID = 'advanced-rename-and-delete-handler';

export const ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME = 'Advanced Rename and Delete Handler';

/**
 * The contract version range this plugin compiled against.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE = '^1';

/**
 * The contract range this plugin REQUIRES before it runs at all — the one declared through
 * `getPluginDependencies()`.
 *
 * Narrower than {@link ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE} on purpose: the read-back arrived in
 * contract `1.1.0`, and a provider older than that would open the dependency gate and then fail every read. Asking
 * for `1.1.0` here turns that into the gate's own "update this plugin" message instead.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_DEPENDENCY_API_VERSION_RANGE = '^1.1.0';

/**
 * The lowest plugin version this plugin REQUIRES, declared through `getPluginDependencies()` beside the contract range.
 *
 * `2.2.0` is the first release that reads the attachment-unit-folder designation through this plugin's API rather than
 * off the `getAvailablePathForAttachments` graft 15.0.0 removed. A 2.1.x provider still publishes contract `1.1.0`, so
 * the range above cannot tell it apart: it would open the gate and then delete a unit folder's contents piecemeal,
 * without any notice. Asking for `2.2.0` gave that user the gate's own "update this plugin" message instead.
 *
 * `3.0.1` is the first release built on `@mnaoumov/obsidian-lib` 6, the major that moved the plugin-API registry from
 * `globalThis.__obsidianDevUtils` to `globalThis.__obsidianLib`. Up to 3.0.0 the provider publishes into the old bag,
 * which this plugin never reads, so the gate sees an enabled plugin with no API and says it is not installed. Asking
 * for `3.0.1` turns that into the "update this plugin" message too, with the button that does it.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_MIN_PLUGIN_VERSION = '3.0.1';

/**
 * What the MIGRATION needs — a single method, published since contract `1.0.0`.
 *
 * Supplied to `watchPluginApi` as the consumer's own contract, which wins over the provider's. The two
 * consumers here need different halves of the API and must be told apart: the migration works against
 * every `^1` provider, while the read-back below does not.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT: ApiContract<SettingsMigrationApi<AdvancedRenameAndDeleteHandlerMigratableSettings>> = {
  migrateSettings: ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.migrateSettings
};

/**
 * The settings a migration proposes, in the provider's own types, which its contract's schemas check. This plugin's
 * {@link MigratableSettings} is assignable to it.
 */
export type AdvancedRenameAndDeleteHandlerMigratableSettings = ProviderMigratableSettings;

/**
 * The half of the provider's API the read-back calls, in the provider's own types, because those are what the
 * contract's schemas check.
 */
export type AdvancedRenameAndDeleteHandlerReadBackApi = Pick<ProviderApi, 'getSettings' | 'isPathIgnored' | 'isTreatedAsAttachment'>;

/**
 * What the READ-BACK needs — the three members contract `1.1.0` added.
 *
 * This is load-bearing rather than decorative. `Advanced Rename and Delete Handler` `1.1.1` publishes
 * contract `1.0.0`, whose own contract declares only `migrateSettings` — so it satisfies `^1` and passes a
 * shape check made against the PROVIDER's contract. Without this one, a user on that released version would
 * be handed an API with no `getSettings` and every read would throw. With it, the record fails the shape
 * check, `PluginApiRef.value` stays `null`, and this plugin falls back to
 * {@link DEFAULT_HANDED_OVER_SETTINGS} until the provider is new enough.
 *
 * Its `getSettings` output schema is contract `1.2.0`'s, which requires `shouldDeleteEmptyNoteFolders`. A `1.1.0`
 * provider (2.2.x) does not return it, so with the `obsidian-lib:validate-plugin-api-payloads` debug switch on, its
 * reads are refused. The gate still admits `1.1.0` on purpose: this plugin never reads that key, and forcing every
 * 2.2.x user to update for a developer-only switch is the worse trade.
 */
export const ADVANCED_RENAME_AND_DELETE_HANDLER_READ_BACK_API_CONTRACT: ApiContract<AdvancedRenameAndDeleteHandlerReadBackApi> = {
  getSettings: ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.getSettings,
  isPathIgnored: ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.isPathIgnored,
  isTreatedAsAttachment: ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.isTreatedAsAttachment
};

/**
 * What this plugin uses while `Advanced Rename and Delete Handler`'s API is not in hand.
 *
 * Rarely reached now that the other plugin is a declared dependency: this plugin's commands, patches and
 * handlers do not load at all until the dependency gate has seen its API. What is left is the gap the gate
 * cannot close — a read made while the provider is unloading, between its API being revoked and this plugin's
 * surface being torn down. A fallback there keeps a read from throwing.
 *
 * These are THIS plugin's own historic defaults rather than the other plugin's, because the values a user
 * configured before 12.0.0 were this plugin's. `emptyFolderBehavior` is the visible case — this plugin has
 * always defaulted to {@link EmptyFolderBehavior.DeleteWithEmptyParents}, while the other plugin defaults to
 * {@link EmptyFolderBehavior.Keep}.
 */
export const DEFAULT_HANDED_OVER_SETTINGS: HandedOverSettings = {
  emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
  notePriorities: [],
  shouldRenameAttachmentFiles: false,
  treatAsAttachmentExtensions: ['.excalidraw.md']
};

/**
 * The provider's spellings of an empty-folder behavior, each mapped to the library enum member with the same value.
 *
 * The provider's copyable `api.d.ts` imports nothing, so it spells the behavior as a string union, while this
 * plugin passes `@mnaoumov/obsidian-lib`'s enum on to the library. The record is total over the union, so a value
 * the provider adds fails to compile here instead of reaching the library unmapped.
 */
const EMPTY_FOLDER_BEHAVIORS: Readonly<Record<ProviderEmptyFolderBehavior, EmptyFolderBehavior>> = {
  Delete: EmptyFolderBehavior.Delete,
  DeleteWithEmptyParents: EmptyFolderBehavior.DeleteWithEmptyParents,
  Keep: EmptyFolderBehavior.Keep
};

/**
 * Narrows the settings the provider hands back to the ones this plugin reads, in this plugin's types.
 *
 * @param settings - The settings, as the provider's `getSettings` returns them.
 * @returns The settings this plugin reads.
 */
export function toHandedOverSettings(settings: ProviderHandedOverSettings): HandedOverSettings {
  return {
    emptyFolderBehavior: EMPTY_FOLDER_BEHAVIORS[settings.emptyFolderBehavior],
    notePriorities: settings.notePriorities,
    shouldRenameAttachmentFiles: settings.shouldRenameAttachmentFiles,
    treatAsAttachmentExtensions: settings.treatAsAttachmentExtensions
  };
}
