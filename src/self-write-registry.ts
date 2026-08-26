/**
 * The paths the plugin is itself about to create in the vault.
 *
 * {@link ExternallyCreatedAttachmentHandlerComponent} reacts to `vault.on('create')` so it can rename
 * attachments other plugins write straight through `vault.createBinary` (issue #59). That event does not
 * say who wrote the file, and the plugin writes attachments too — so without this registry the plugin
 * would re-process its own saves, which for a `${prompt}` template means a second prompt for every
 * attachment, and for a `${date}`/`${uuid}` template means an endless spurious rename.
 *
 * "Recompute the path and skip when it already matches" is NOT a substitute: the very tokens that make
 * re-processing harmful are the ones that resolve to something different on every evaluation.
 *
 * Registration is by path rather than by a depth counter around the write, because a write can await
 * for a long time (the `${prompt}` modal waits on the user) and a counter would suppress every
 * genuinely foreign creation happening in that window.
 */

/**
 * How long a registered path stays claimed. Generous — it only has to outlive the dispatch of the
 * `create` event for that path — and entries are also consumed on match, so this is a leak backstop
 * rather than a timing dependency.
 */
const PRUNE_THRESHOLD_IN_MILLISECONDS = 60_000;

class SelfWriteRegistry {
  private readonly registeredAtByPath = new Map<string, number>();

  /**
   * Reports whether `path` was claimed by {@link register}, and un-claims it.
   *
   * @param path - The path of the newly created file.
   * @returns `true` when the plugin wrote the file itself.
   */
  public consume(path: string): boolean {
    this.prune();
    return this.registeredAtByPath.delete(path);
  }

  /**
   * Claims `path` as a plugin-initiated write, matching a later {@link consume} for the same path.
   *
   * @param path - The vault path the plugin is about to create.
   */
  public register(path: string): void {
    this.prune();
    this.registeredAtByPath.set(path, Date.now());
  }

  private prune(): void {
    const cutoff = Date.now() - PRUNE_THRESHOLD_IN_MILLISECONDS;
    for (const [path, registeredAt] of this.registeredAtByPath) {
      if (registeredAt < cutoff) {
        this.registeredAtByPath.delete(path);
      }
    }
  }
}

/**
 * The single registry for this plugin instance.
 *
 * A module-level instance rather than a constructor-threaded one: the claim has to be made at the
 * `vault.create`/`createBinary` call itself, and those calls sit as deep as the preview modal, which is
 * reached only through the public {@link TokenEvaluatorContext}. Threading it there would put internal
 * plumbing on the documented custom-token surface and touch every `Substitutions` construction, to hold
 * state that is already self-expiring. Obsidian re-evaluates the plugin bundle on every load, so this
 * cannot outlive a reload — the same reason `Substitutions.registeredTokens` is static.
 */
export const selfWriteRegistry = new SelfWriteRegistry();
