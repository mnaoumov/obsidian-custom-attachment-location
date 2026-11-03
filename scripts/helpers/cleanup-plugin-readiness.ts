/**
 * The API publication state read by the desktop vault cleanup.
 */
export interface CleanupPluginApiRecord {
  readonly api: unknown;
  readonly isRevoked: boolean;
}

/**
 * A snapshot of the plugin and dependency after a cleanup reload.
 */
export interface IsCleanupPluginReadyParams {
  readonly currentPlugin: unknown;
  readonly dependencyApis: readonly CleanupPluginApiRecord[];
  readonly dependencyPlugin: unknown;
  readonly pluginApis: readonly CleanupPluginApiRecord[];
  readonly previousApis: readonly unknown[];
  readonly previousPlugin: unknown;
}

/**
 * Checks that cleanup has a new feature surface backed by its live dependency.
 *
 * Self-contained so the integration harness can serialize it into Obsidian.
 *
 * @param params - The current registry and the surface captured before disabling.
 * @returns Whether the next file can use the reloaded plugin.
 */
export function isCleanupPluginReady(params: IsCleanupPluginReadyParams): boolean {
  return Boolean(params.currentPlugin)
    && params.currentPlugin !== params.previousPlugin
    && Boolean(params.dependencyPlugin)
    && params.dependencyApis.some((record) => !record.isRevoked)
    && params.pluginApis.some((record) => !record.isRevoked && !params.previousApis.includes(record.api));
}
