/**
 * The API this plugin publishes for other plugins to call.
 *
 * Copy this file into your own plugin: it imports nothing at all, so it costs you no dependency on this plugin and none
 * on `@mnaoumov/obsidian-lib`. That is why {@link EmptyFolderBehavior} — which the plugin itself takes from that library as
 * an enum — is inlined below as a plain string-literal union. It carries the same runtime values the plugin uses.
 *
 * The API is reached through the `@mnaoumov/obsidian-lib` cross-plugin API registry, keyed by the plugin id
 * `advanced-rename-and-delete-handler` and version-negotiated against its CONTRACT version, which moves independently of
 * the plugin's own `manifest.version`. `1.1.0` added the three read-back members to `1.0.0`'s `migrateSettings`, and
 * `1.2.0` added {@link HandedOverSettings.shouldDeleteEmptyNoteFolders}, both purely additively, so ask for `^1`. The README's `For plugin developers` section shows both routes: `watchPluginApi` for a
 * consumer that already has `@mnaoumov/obsidian-lib`, and the library-free registry read for one that does not.
 */

/**
 * What to do with a folder a deletion or a move has left empty.
 *
 * - `Keep` leaves it.
 * - `Delete` deletes it.
 * - `DeleteWithEmptyParents` deletes it, and then every parent that deleting it left empty in turn.
 */
export type EmptyFolderBehavior = 'Delete' | 'DeleteWithEmptyParents' | 'Keep';

/**
 * This plugin's API, as a consumer sees it.
 */
export interface AdvancedRenameAndDeleteHandlerApi {
  /**
   * The settings this plugin holds right now, as plain data.
   *
   * Synchronous and read live on every call, so there is nothing to invalidate and nothing to subscribe to:
   * a consumer calls it from inside a `checkCallback(isChecking): boolean`, a settings row's `disabled` /
   * `visible` predicate, or a loop over vault files, none of which can `await`.
   *
   * The arrays are copies, so writing to one changes nothing here.
   *
   * @returns The current values.
   */
  getSettings: () => HandedOverSettings;

  /**
   * Whether this plugin leaves the path alone entirely, per its include and exclude lists.
   *
   * Handed over as a predicate rather than left to the caller to recompute from
   * {@link HandedOverSettings.excludePaths} / {@link HandedOverSettings.includePaths}: every plugin bundles
   * its own `@mnaoumov/obsidian-lib`, so two copies of the matching code are two copies that can drift apart.
   *
   * @param path - The path to test, from the vault root.
   * @returns `true` when the path is ignored.
   */
  isPathIgnored: (path: string) => boolean;

  /**
   * Whether the path names an attachment even though its extension says otherwise — an `Excalidraw` drawing
   * being the case that motivated the setting, recognized by its `.excalidraw.md` extension or, through a
   * `property:excalidraw-plugin` entry, by its frontmatter.
   *
   * A `property:` entry reads the metadata cache, so a markdown file Obsidian has not indexed yet matches no
   * such entry and is answered `false` until it has.
   *
   * A predicate for the same reason as {@link AdvancedRenameAndDeleteHandlerApi.isPathIgnored}: the matching
   * stays in one place rather than being re-derived from
   * {@link HandedOverSettings.treatAsAttachmentExtensions} by each consumer's own library copy.
   *
   * @param path - The path to test, from the vault root.
   * @returns `true` when the path is treated as an attachment.
   */
  isTreatedAsAttachment: (path: string) => boolean;

  /**
   * Offers the user a set of settings values another plugin proposes, and applies what they approve.
   *
   * Resolves only once the dialog is closed, so the caller learns whether the migration happened and can
   * set — or withhold — its own one-shot flag on that answer.
   *
   * @param params - The proposal.
   * @returns What the user approved.
   */
  migrateSettings: (params: MigrateSettingsParams) => Promise<MigrateSettingsResult>;
}

/**
 * The settings this plugin owns on its consumers' behalf, and hands back through
 * {@link AdvancedRenameAndDeleteHandlerApi.getSettings}.
 *
 * A consumer that hands its rename/delete handler over does not stop caring about these values — they drive
 * features of its own that have nothing to do with a rename or a delete. Reading them back here is what
 * keeps it from having to shadow settings this plugin now owns.
 */
export interface HandedOverSettings {
  /**
   * What to do with a folder a deletion or a move has left empty.
   */
  readonly emptyFolderBehavior: EmptyFolderBehavior;

  /**
   * Paths this plugin leaves alone entirely.
   */
  readonly excludePaths: readonly string[];

  /**
   * Paths this plugin is limited to. Empty means the whole vault.
   */
  readonly includePaths: readonly string[];

  /**
   * Which surviving note adopts an attachment a deletion would otherwise strand, highest priority first.
   */
  readonly notePriorities: readonly string[];

  /**
   * Whether an attachment that collides with an existing file at the destination replaces it.
   */
  readonly shouldDeleteConflictingAttachments: boolean;

  /**
   * Whether {@link HandedOverSettings.emptyFolderBehavior} also applies to the folder a deleted note leaves empty,
   * not only to the attachment folders it leaves empty. Added in contract `1.2.0`.
   */
  readonly shouldDeleteEmptyNoteFolders: boolean;

  /**
   * Whether deleting a note also deletes the attachments only that note referenced.
   */
  readonly shouldHandleDeletions: boolean;

  /**
   * Whether renames and moves are handled at all.
   */
  readonly shouldHandleRenames: boolean;

  /**
   * Whether renaming a note renames the attachment files that travel with it.
   */
  readonly shouldRenameAttachmentFiles: boolean;

  /**
   * Whether renaming a note renames (or moves) its attachment folder alongside it.
   */
  readonly shouldRenameAttachmentFolder: boolean;

  /**
   * Whether an attachment that survives a deletion is moved into the surviving note's attachment folder.
   */
  readonly shouldRescueSharedAttachments: boolean;

  /**
   * Whether renaming a note rewrites the display text of the links that pointed at its old name.
   */
  readonly shouldUpdateFileNameAliases: boolean;

  /**
   * Entries that make a file an attachment even though its extension says otherwise: an extension such as
   * `.excalidraw.md`, or a `property:name` / `property:name=value` frontmatter match.
   */
  readonly treatAsAttachmentExtensions: readonly string[];
}

/**
 * The settings a consumer may propose. Every member is optional: a consumer proposes only what it held.
 *
 * Derived from {@link HandedOverSettings} rather than restated, so what can be proposed and what can be read
 * back stay the same set — a fact the compiler holds, instead of two lists that have to be kept in step.
 */
export type MigratableSettings = Partial<HandedOverSettings>;

/**
 * Parameters for {@link AdvancedRenameAndDeleteHandlerApi.migrateSettings}.
 */
export interface MigrateSettingsParams {
  /**
   * The values the calling plugin proposes.
   */
  readonly proposedSettings: MigratableSettings;

  /**
   * The `manifest.id` of the plugin making the proposal. Shown in the dialog, so the user knows whose
   * settings they are being offered.
   */
  readonly sourcePluginId: string;
}

/**
 * The outcome of {@link AdvancedRenameAndDeleteHandlerApi.migrateSettings}.
 */
export interface MigrateSettingsResult {
  /**
   * Whether the user approved the migration. `false` means they cancelled and nothing was written — the
   * caller should NOT record the migration as done.
   */
  readonly isApplied: boolean;
}
