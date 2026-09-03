/**
 * @file
 *
 * Which plugin wrote which path, recorded at the write and read back when the `create` event arrives.
 *
 * The sibling {@link selfWriteRegistry} answers "did THIS plugin write it?"; this one answers "then who
 * did?", which is what the two list modes of `RenameAttachmentsCreatedByOtherPluginsMode` need (issue #77).
 *
 * The record has to be made at the write CALL rather than in the `create` handler. `Vault.create` and
 * `Vault.createBinary` await `adapter.write`/`adapter.writeBinary`, and the `create` event is dispatched
 * from the adapter's reconciliation of that write — so by the time the handler runs, the calling plugin's
 * frame has long left the stack. At the call it is one frame down.
 *
 * Path-keyed rather than a counter around the write, for the same reason the self-write registry is: a
 * write can await for a long time, and a counter would misattribute every unrelated creation in that
 * window.
 */

/**
 * How long a recorded path stays attributed.
 *
 * It only has to outlive the dispatch of the `create` event for that path, and entries are consumed on
 * match, so this is a leak backstop rather than a timing dependency. Matches the self-write registry.
 */
const PRUNE_THRESHOLD_IN_MILLISECONDS = 60_000;

interface ForeignWrite {
  readonly pluginId: string;
  readonly registeredAt: number;
}

class ForeignWriteRegistry {
  private readonly writeByPath = new Map<string, ForeignWrite>();

  /**
   * Reports which plugin registered `path`, and un-registers it.
   *
   * @param path - The path of the newly created file.
   * @returns The creating plugin's id, or `null` when the write was never attributed.
   */
  public consume(path: string): null | string {
    this.prune();
    const foreignWrite = this.writeByPath.get(path);
    this.writeByPath.delete(path);
    return foreignWrite?.pluginId ?? null;
  }

  /**
   * Records `path` as written by `pluginId`, matching a later {@link consume} for the same path.
   *
   * The last writer wins: a plugin that resolves a path and then writes it goes through several patched
   * entry points for the one file, and the innermost call is the one that actually created it.
   *
   * @param path - The vault path being written.
   * @param pluginId - The `manifest.id` of the plugin performing the write.
   */
  public register(path: string, pluginId: string): void {
    this.prune();
    this.writeByPath.set(path, { pluginId, registeredAt: Date.now() });
  }

  private prune(): void {
    const cutoff = Date.now() - PRUNE_THRESHOLD_IN_MILLISECONDS;
    for (const [path, foreignWrite] of this.writeByPath) {
      if (foreignWrite.registeredAt < cutoff) {
        this.writeByPath.delete(path);
      }
    }
  }
}

/**
 * The single registry for this plugin instance.
 *
 * A module-level instance for the same reason {@link selfWriteRegistry} is one: the record is made deep
 * inside a monkey-patched vault method, and threading state down to it would put internal plumbing on
 * surfaces that have no business carrying it. Obsidian re-evaluates the plugin bundle on every load, so
 * this cannot outlive a reload.
 */
export const foreignWriteRegistry = new ForeignWriteRegistry();
