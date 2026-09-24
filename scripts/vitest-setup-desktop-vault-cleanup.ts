/// <reference types="obsidian-integration-testing/vitest/typings" />

import type { TAbstractFile } from 'obsidian';

import {
  existsSync,
  readFileSync,
  writeFileSync
} from 'node:fs';
import {
  join,
  relative
} from 'node:path';
import { evalInObsidian } from 'obsidian-integration-testing';
import {
  afterAll,
  beforeAll,
  expect,
  inject
} from 'vitest';

/**
 * The Node-side ceiling on the whole cleanup closure, kept under the desktop project's 120s `hookTimeout`.
 *
 * Every step inside the closure has its own ceiling (their sum is ~65s), so a closure that outlives this is not one
 * slow step: it is a renderer that has stopped running JavaScript at all, or an instance that died under it. Ending
 * the hook here, with a message that says so, is the difference between a report and vitest's bare
 * `Hook timed out in 120000ms`.
 */
const CLEANUP_CLOSURE_TIMEOUT_IN_MILLISECONDS = 90_000;

/**
 * How long the per-file liveness probe waits for the instance to evaluate `true`.
 */
const LIVENESS_PROBE_TIMEOUT_IN_MILLISECONDS = 15_000;

/**
 * Where the liveness probe keeps its state across files: a dotfile in the run's temporary vault.
 *
 * Every file gets a fresh module graph, so nothing held in this module survives to the next file, and the vault path
 * is the one value unique to this run that every file can reach (`inject`). A dotfile is invisible to Obsidian, so the
 * per-file wipe below never sees it, and the harness removes the whole vault at teardown.
 */
const LIVENESS_STATE_FILE_NAME = '.vitest-instance-liveness.json';

/**
 * Marks a cleanup step that never settled. Shared by the closure's report and the check that fails the file on it.
 */
const STUCK_PREFIX = 'STUCK: ';

/**
 * Set when this file's `beforeAll` found the instance gone, so its `afterAll` does not try to clean up after it.
 */
const thisFile = {
  isInstanceGone: false
};

interface InstanceLivenessState {
  /**
   * The last file the instance answered the probe for.
   */
  readonly lastAnsweredForFilePath?: string;
  /**
   * The first file to find the instance gone, which carries the full statement of it.
   */
  readonly lostReportedByFilePath?: string;
}

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

/*
 * Checks, before each file, that the shared instance still answers, and says so plainly when it does not.
 *
 * When the instance dies mid-run, every later file otherwise fails on its own with `TypeError: fetch failed` /
 * `connect ECONNREFUSED` from the transport. That reads as a dozen unrelated suites broken by the change under test,
 * when none of them ran, and the one file that actually took the instance down is buried among them. So the FIRST
 * file to find the instance gone fails with the whole statement — gone, since which file, and that this file did not
 * run — and every later file fails with a one-line pointer back to it.
 */
beforeAll(async () => {
  const filePath = expect.getState().testPath ?? '(unknown file)';
  const state = readLivenessState();

  if (state.lostReportedByFilePath !== undefined) {
    thisFile.isInstanceGone = true;
    throw new Error(
      `Did not run: the shared Obsidian instance was already gone. See the failure of ${toDisplayPath(state.lostReportedByFilePath)}, the first file to find it so.`
    );
  }

  try {
    await probeInstance();
  } catch (error) {
    thisFile.isInstanceGone = true;
    writeLivenessState({ ...state, lostReportedByFilePath: filePath });
    const lastAnsweredFor = state.lastAnsweredForFilePath === undefined
      ? 'It never answered for any file in this run'
      : `It last answered for ${toDisplayPath(state.lastAnsweredForFilePath)}, so THAT file took it down: read its failure, not this one`;
    throw new Error(
      `The shared Obsidian instance is gone, so this file did not run, and no file after it will. ${lastAnsweredFor}.`,
      { cause: error }
    );
  }

  writeLivenessState({ lastAnsweredForFilePath: filePath });
});

afterAll(async () => {
  if (thisFile.isInstanceGone) {
    // Nothing ran, and the `beforeAll` has already said why; a cleanup against a dead instance would only add noise.
    return;
  }

  /*
   * Probe first, under its own short ceiling. An instance that died DURING this file does not fail an evaluation
   * sent to it: measured, the cleanup's evaluation just hung until the Node-side ceiling below, which is how a dead
   * instance once presented as this hook timing out at 120s. The probe turns that into a fast failure that says
   * what happened, and blames the right file — this one.
   */
  try {
    await probeInstance();
  } catch (error) {
    throw new Error(
      '[vault-cleanup] the shared Obsidian instance stopped answering while this file ran, so this file is what took it down. The cleanup did not run, and the files after this one will not either.',
      { cause: error }
    );
  }

  const report = await withNodeDeadline(
    evalInObsidian({
      async callback({ app, stuckPrefix }): Promise<string[]> {
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
        /*
         * The ceilings on the three steps below that used to be unbounded. Each normally settles well inside a
         * second; the wipe touches the ~12 entries one file leaves behind. They exist so a step that NEVER settles
         * cannot hold this one evaluation open until vitest's hook timeout, which is how one stuck step once took the
         * whole instance down, and the eleven files after it with it.
         */
        const PLUGIN_TOGGLE_TIMEOUT_IN_MILLISECONDS = 10_000;
        const VAULT_WIPE_TIMEOUT_IN_MILLISECONDS = 30_000;
        const VAULT_ROOT_PATH = '/';

        const pending = new Set<string>();

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
         * Runs one step under its own ceiling, and records it as stuck instead of waiting past it.
         *
         * The step itself is not cancelled — nothing here can cancel a pending plugin toggle — but this closure
         * returns, so the evaluation ends and the transport stays up for the next file.
         */
        async function runBounded(stepName: string, step: () => Promise<unknown>, timeoutInMilliseconds: number): Promise<void> {
          let timer: number | undefined;
          const didTimeout = await Promise.race([
            step().then(() => false).catch(() => false),
            new Promise<boolean>((resolve) => {
              timer = window.setTimeout(() => {
                resolve(true);
              }, timeoutInMilliseconds);
            })
          ]);
          window.clearTimeout(timer);
          if (didTimeout) {
            pending.add(`${stuckPrefix}${stepName} did not settle within ${String(timeoutInMilliseconds)}ms`);
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

        // A dialog the sweep could not close is the likeliest owner of a queue entry that never resolves, so name it.
        for (const modalEl of document.querySelectorAll('.modal-container')) {
          pending.add(`MODAL-LEFT-OPEN: ${modalEl.querySelector('.modal-title')?.textContent ?? '(untitled)'}`);
        }

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
        await runBounded('disabling the plugin', () => app.plugins.disablePlugin(PLUGIN_ID), PLUGIN_TOGGLE_TIMEOUT_IN_MILLISECONDS);
        await runBounded('wiping the vault', () => removeAll(loadedEntries()), VAULT_WIPE_TIMEOUT_IN_MILLISECONDS);
        await runBounded('enabling the plugin', () => app.plugins.enablePlugin(PLUGIN_ID), PLUGIN_TOGGLE_TIMEOUT_IN_MILLISECONDS);

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
      },
      input: {
        stuckPrefix: STUCK_PREFIX
      }
    }),
    CLEANUP_CLOSURE_TIMEOUT_IN_MILLISECONDS,
    `[vault-cleanup] the cleanup did not return within ${String(CLEANUP_CLOSURE_TIMEOUT_IN_MILLISECONDS)}ms although every step in it is bounded, so the renderer has stopped running JavaScript or the instance died under it`
  );

  if (report.some((entry) => entry.startsWith(STUCK_PREFIX))) {
    // A step that never settled leaves the instance in a state the next file cannot trust, and this file is what
    // Left it there, so this file is the one that fails — while the instance is still up to say so.
    throw new Error(`[vault-cleanup] this file left the instance unable to clean up: ${report.join(', ')}`);
  }

  if (report.length > 0) {
    // Not a failure on its own — the drain above absorbed it — but worth seeing, because it names the
    // Suite that would otherwise have stalled the next one.
    console.warn(`[vault-cleanup] this file left behind: ${report.join(', ')}`);
  }
});

function getLivenessStatePath(): string {
  return join(inject('temporaryVaultPath'), LIVENESS_STATE_FILE_NAME);
}

async function probeInstance(): Promise<void> {
  await withNodeDeadline(
    evalInObsidian({
      callback(): boolean {
        return true;
      }
    }),
    LIVENESS_PROBE_TIMEOUT_IN_MILLISECONDS,
    `the instance did not evaluate \`true\` within ${String(LIVENESS_PROBE_TIMEOUT_IN_MILLISECONDS)}ms`
  );
}

function readLivenessState(): InstanceLivenessState {
  const statePath = getLivenessStatePath();
  return existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf-8')) as InstanceLivenessState : {};
}

function toDisplayPath(filePath: string): string {
  return relative(process.cwd(), filePath).replaceAll('\\', '/');
}

/**
 * Settles with `promise`, or rejects with `message` once the ceiling passes, whichever comes first.
 *
 * The losing promise is not cancelled; `Promise.race` still holds a handler on it, so its later rejection is never
 * reported as unhandled.
 *
 * @param promise - What to wait for.
 * @param timeoutInMilliseconds - The ceiling.
 * @param message - The rejection's message when the ceiling wins.
 * @returns What `promise` settles with.
 */
async function withNodeDeadline<T>(promise: Promise<T>, timeoutInMilliseconds: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error(message));
        }, timeoutInMilliseconds);
      })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function writeLivenessState(state: InstanceLivenessState): void {
  writeFileSync(getLivenessStatePath(), JSON.stringify(state));
}
