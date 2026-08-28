import type { TAbstractFile } from 'obsidian';

import { evalInObsidian } from 'obsidian-integration-testing';
import { afterAll } from 'vitest';

interface ObsidianDevUtilsGlobal {
  readonly __obsidianDevUtils?: Record<string, ObsidianDevUtilsStateWrapper | undefined>;
}

interface ObsidianDevUtilsStateWrapper {
  readonly value?: unknown;
}

/**
 * One entry of obsidian-dev-utils' global operation queue, as seen from outside the library.
 *
 * Only the shape this file reads is modeled; the library does not export the type. Declared at module
 * scope rather than inside the callback because types are erased before the callback is serialized.
 */
interface OperationQueueItem {
  readonly operationName?: string;
  readonly timeoutInMilliseconds?: number;
}

interface OperationQueueState {
  readonly items?: readonly OperationQueueItem[];
}

/*
 * Returns the shared Obsidian instance to a pristine state after every `integration-tests:desktop` file.
 *
 * The desktop project runs all its files serially (`fileParallelism: false`) against ONE owned Obsidian
 * instance holding ONE vault, and no test file puts back what it changed. Two things therefore pile up
 * across a run:
 *
 * - Vault entries. Left alone the vault grows to ~400 entries, and every vault-wide operation under test
 *   ("Delete unused attachments in entire vault", "Collect attachments", the link-update progress
 *   reporter) scales with that size.
 * - Plugin settings. Each file writes straight onto the live settings object, so a later file inherits
 *   whatever the ~30 before it left — an attachment path carrying a `${prompt}` token, a rescue toggle,
 *   a note-priority list.
 *
 * Third, and the one that actually caused failures rather than merely risking them: obsidian-dev-utils'
 * operation queue. See the drain below.
 *
 * Measured with this hook in place, the vault stays flat at ~12 entries instead of reaching ~400, and
 * vault/metadata/workspace handler counts are identical after every file.
 *
 * Wired into the desktop project's `setupFiles` (see `scripts/vitest-config.ts`), which vitest evaluates
 * once per test file, so this `afterAll` runs at the end of each file rather than once per run.
 *
 * Deliberately NOT wired into `integration-tests:demo-vault` or `capture-screenshots:desktop`: both spread
 * the same context object but open a vault whose contents ARE the fixture.
 */

afterAll(async () => {
  const pendingOperationNames = await evalInObsidian({
    async callback({ app }): Promise<string[]> {
      // The callback is serialized and evaluated inside Obsidian, so it closes over nothing: every
      // Constant and helper it uses has to be declared in here.
      const MODAL_DISMISS_SETTLE_IN_MILLISECONDS = 200;
      const PLUGIN_ID = 'obsidian-custom-attachment-location';
      const HANDLER_REGISTRATION_TIMEOUT_IN_MILLISECONDS = 10_000;
      const QUEUE_DRAIN_POLL_IN_MILLISECONDS = 200;
      /*
       * Deliberately SHORT. A `Handle delete` entry can hold the shared queue for its own 60s ceiling,
       * and each file's cleanup queues several, so a backlog frequently outlives any wait worth doing
       * here — measured, a 60s budget spent ~28 minutes per run waiting and made results worse, not
       * better. This absorbs the common short backlog and otherwise reports what it saw and moves on.
       */
      const QUEUE_DRAIN_TIMEOUT_IN_MILLISECONDS = 5000;
      const VAULT_ROOT_PATH = '/';

      function loadedEntries(): TAbstractFile[] {
        return app.vault
          .getAllLoadedFiles()
          .filter((file) => file.path !== VAULT_ROOT_PATH)
          // Deepest first, so a folder is always empty by the time it is deleted.
          .sort((a, b) => b.path.length - a.path.length);
      }

      async function removeAll(files: TAbstractFile[]): Promise<void> {
        for (const file of files) {
          try {
            // Force, so entries land nowhere: a vault-local `.trash` would accumulate exactly the
            // Files this cleanup exists to get rid of.
            await app.vault.delete(file, true);
          } catch {
            // Already gone, taken by a parent folder deleted earlier in the same loop.
          }
        }
      }

      /*
       * Cancel any dialog a test left standing, BEFORE unloading anything. The plugin runs its work on
       * an internal queue and a modal is one of its steps, so an unanswered one keeps that entry
       * pending forever and every later file waits behind it — which is how a single suite that gave up
       * on its modal took the next three unrelated files down with 60s timeouts each.
       *
       * Only the modal's own close affordance is used, never its content buttons: clicking those blindly
       * ACTIVATES whatever the dialog offers, and on the settings dialog that means toggling plugin
       * settings, which are persisted — poisoning every later file far worse than the standing modal
       * did. Closing this way still runs the modal's `onClose`, which is what resolves the queue entry.
       */
      /*
       * Obsidian's settings dialog is not closed by the sweep below — it is not an ordinary modal with
       * a close button — so it is closed through its own API. A suite that opens settings and does not
       * close them leaks a live dialog into every later file.
       */
      app.setting.close();

      for (const closeEl of document.querySelectorAll<HTMLElement>('.modal-container .modal-close-button')) {
        closeEl.click();
      }
      for (const modalEl of document.querySelectorAll('.modal-container')) {
        modalEl.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Escape' }));
      }
      await sleep(MODAL_DISMISS_SETTLE_IN_MILLISECONDS);

      /*
       * Drain obsidian-dev-utils' operation queue before letting the next file start.
       *
       * That queue is a GLOBAL singleton — `getObsidianDevUtilsState('queue')` on `globalThis`, shared
       * by every plugin using the library — and it is a promise chain: each entry runs only after the
       * previous one settles. So an entry this file left in flight does not stay this file's problem.
       * The next file's command is accepted (`executeCommandById` returns true) and then sits behind it,
       * producing no modal and no notice, until the stalled entry hits its own timeout. That is the
       * burst of consecutive unrelated failures this suite kept showing.
       *
       * Waiting here is bounded: every entry carries its own timeout, so the chain always advances.
       * Disabling the plugin does NOT clear this — the queue outlives the plugin instance.
       */
      const queueState = (globalThis as ObsidianDevUtilsGlobal).__obsidianDevUtils?.['queue']?.value as OperationQueueState | undefined;
      const pending = new Set<string>();

      async function drainQueue(): Promise<void> {
        const drainDeadline = Date.now() + QUEUE_DRAIN_TIMEOUT_IN_MILLISECONDS;
        while ((queueState?.items?.length ?? 0) > 0 && Date.now() < drainDeadline) {
          for (const item of queueState?.items ?? []) {
            pending.add(item.operationName ?? '(unnamed)');
          }
          await sleep(QUEUE_DRAIN_POLL_IN_MILLISECONDS);
        }
      }

      await drainQueue();

      /*
       * The plugin is disabled around the wipe: deletions then run with no handlers listening, so no
       * rescue moves an attachment back out and no empty-folder pass races the loop, and re-enabling
       * reloads the settings from `data.json` — untouched, because the suites only mutate the in-memory
       * object. Measured, wiping with the plugin live instead costs ~3x the wall clock (599s vs 186s)
       * and MORE failures, because every deletion queues handler work that then has to drain.
       */
      await app.plugins.disablePlugin(PLUGIN_ID);
      await removeAll(loadedEntries());
      await app.plugins.enablePlugin(PLUGIN_ID);

      /*
       * Wait for the plugin to reappear in obsidian-dev-utils' rename/delete handler registry.
       *
       * That registry is another global singleton keyed by plugin id: registering `set`s the key,
       * unregistering `delete`s it, and `shouldInvokeHandler()` only lets the FIRST key's plugin handle
       * anything. Unload and load are both async, so the old instance's `delete` can land AFTER the new
       * instance's `set` — leaving the map EMPTY, at which point no plugin is the main handler and
       * renames and deletions stop being handled at all for the rest of the session. That is invisible
       * except as a suite reporting a rename that updated no links and raised no notice, which is what
       * `link-update-progress` and `attachment-rescue` kept doing, in every retry of the same run.
       */
      function handlerIds(): string[] {
        const handlersMap = (globalThis as ObsidianDevUtilsGlobal).__obsidianDevUtils?.['renameDeleteHandlersMap']?.value;
        return handlersMap instanceof Map ? [...handlersMap.keys()].map(String) : [];
      }

      function isPluginRegisteredAsHandler(): boolean {
        /*
         * FIRST, not merely present: `shouldInvokeHandler()` compares the plugin id against
         * `[...renameDeleteHandlersMap.keys()][0]`, so anything registered ahead of this plugin silently
         * takes over rename/delete handling — and reloading the plugin cannot fix it, because the
         * reload only re-adds this plugin's own key at the END of an insertion-ordered map.
         */
        return handlerIds()[0] === PLUGIN_ID;
      }

      const registrationDeadline = Date.now() + HANDLER_REGISTRATION_TIMEOUT_IN_MILLISECONDS;
      while (!isPluginRegisteredAsHandler() && Date.now() < registrationDeadline) {
        await sleep(QUEUE_DRAIN_POLL_IN_MILLISECONDS);
      }

      if (!isPluginRegisteredAsHandler()) {
        pending.add(`HANDLER-REGISTRY: [${handlerIds().join(', ')}]`);
      }

      return [...pending];
    }
  });

  if (pendingOperationNames.length > 0) {
    // Not a failure on its own — the drain above absorbed it — but worth seeing, because it names the
    // Suite that would otherwise have stalled the next one.
    console.warn(`[vault-cleanup] drained queue entries left behind: ${pendingOperationNames.join(', ')}`);
  }
});
