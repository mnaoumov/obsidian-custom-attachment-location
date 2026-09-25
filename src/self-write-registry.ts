/**
 * The paths the plugin is itself about to create in the vault.
 *
 * {@link ExternallyCreatedAttachmentHandlerComponent} reacts to `vault.on('create')` so it can rename
 * attachments other plugins write straight through `vault.createBinary` (issue #59). That event does not
 * say who wrote the file, and the plugin writes attachments too — so without this registry the plugin
 * would re-process its own saves, which for a `{{prompt}}` template means a second prompt for every
 * attachment, and for a `{{date}}`/`{{uuid}}` template means an endless spurious rename.
 *
 * "Recompute the path and skip when it already matches" is NOT a substitute: the very tokens that make
 * re-processing harmful are the ones that resolve to something different on every evaluation.
 *
 * Registration is by path rather than by a depth counter around the write, because a write can await
 * for a long time (the `{{prompt}}` modal waits on the user) and a counter would suppress every
 * genuinely foreign creation happening in that window.
 */

/**
 * How long a registered path stays claimed. Generous — it only has to outlive the dispatch of the
 * `create` event for that path — and entries are also consumed on match, so this is a leak backstop
 * rather than a timing dependency.
 */
const PRUNE_THRESHOLD_IN_MILLISECONDS = 60_000;

/**
 * What a claim on a path says about the file that is about to be created there.
 */
export enum SelfWriteClaim {
  /**
   * Nothing claimed the path.
   */
  None = 'None',

  /**
   * The plugin resolved the path for a caller outside its own pipeline — someone asking through the patched
   * `vault.getAvailablePathForAttachments` — and that caller chose the file name, which the resolver passes
   * through untouched.
   *
   * Such a claim holds only while core Obsidian is the writer: its audio recorder and its file imports ask
   * exactly this way and must not be renamed a second time. A PLUGIN that asks for a folder and then writes
   * its own name into it — Excalidraw's `Pasted Image <date>.png` (issue #65) — is the very case
   * `renameAttachmentsCreatedByOtherPluginsMode` exists for, and the plugin named nothing there.
   */
  OutsideCaller = 'OutsideCaller',

  /**
   * The plugin is about to write the file itself, under a name it chose or accepted.
   */
  Plugin = 'Plugin'
}

interface Registration {
  readonly claim: SelfWriteClaim;
  readonly registeredAt: number;
}

class SelfWriteRegistry {
  private readonly registrationByPath = new Map<string, Registration>();

  /**
   * Reports how `path` was claimed by {@link register}, and un-claims it.
   *
   * @param path - The path of the newly created file.
   * @returns The claim, or {@link SelfWriteClaim.None} when nothing claimed the path.
   */
  public consume(path: string): SelfWriteClaim {
    this.prune();
    const registration = this.registrationByPath.get(path);
    this.registrationByPath.delete(path);
    return registration?.claim ?? SelfWriteClaim.None;
  }

  /**
   * Tells whether `path` is claimed as resolved for an outside caller, leaving the claim in place.
   *
   * The write attribution asks this at the write, before the `create` event consumes the claim, because
   * only a write to such a path needs its creating plugin identified when no list mode asks for it.
   *
   * @param path - The vault path being written.
   * @returns Whether the claim is {@link SelfWriteClaim.OutsideCaller}.
   */
  public hasOutsideCallerClaim(path: string): boolean {
    this.prune();
    return this.registrationByPath.get(path)?.claim === SelfWriteClaim.OutsideCaller;
  }

  /**
   * Claims `path`, matching a later {@link consume} for the same path. A later claim on the same path
   * replaces an earlier one.
   *
   * @param path - The vault path about to be created.
   * @param claim - What kind of claim it is.
   */
  public register(path: string, claim: SelfWriteClaim.OutsideCaller | SelfWriteClaim.Plugin = SelfWriteClaim.Plugin): void {
    this.prune();
    this.registrationByPath.set(path, { claim, registeredAt: Date.now() });
  }

  private prune(): void {
    const cutoff = Date.now() - PRUNE_THRESHOLD_IN_MILLISECONDS;
    for (const [path, registration] of this.registrationByPath) {
      if (registration.registeredAt < cutoff) {
        this.registrationByPath.delete(path);
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
