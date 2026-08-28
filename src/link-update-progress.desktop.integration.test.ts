import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

interface LinkUpdateProgressResult {
  /**
   * Every notice text seen during the rename, not just the progress ones.
   *
   * An empty `capturedMessages` says only that no progress notice was observed. Knowing whether ANY
   * notice reached the DOM separates "the reporter never fired" from "the capture missed it".
   */
  readonly allNoticeTexts: readonly string[];
  readonly capturedMessages: readonly string[];
  readonly lingeringProgressNoticeCount: number;
  readonly settingsFound: boolean;
  readonly sourceCount: number;
  readonly sourceRewritten: boolean;
  readonly targetRenamed: boolean;
}

interface ObsidianDevUtilsGlobal {
  readonly __obsidianDevUtils?: Record<string, OperationQueueWrapper | undefined>;
}

/**
 * The obsidian-dev-utils global operation queue, as seen from outside the library.
 *
 * Only the shape read here is modeled; the library does not export the type. Declared at module scope
 * because types are erased before the callback is serialized into Obsidian.
 */
interface OperationQueueState {
  readonly items?: readonly unknown[];
}

/*
 * End-to-end coverage for issue #25 ("A better links update notification"): when the plugin's
 * `RenameDeleteHandlerComponent` updates links across the backlink source notes of a renamed file, the
 * consumer-supplied `linkUpdateProgressReporter` (wired in `plugin.ts` via
 * `createLinkUpdateProgressReporter`) must surface a persistent, in-place "Updating links: N/M - ..."
 * notice so the user knows exactly when the link updates finish.
 *
 * The observable effect asserted here is the notice DOM itself: a `MutationObserver` collects every
 * `.notice` text containing "Updating links:" while a target with THREE backlinks is renamed, then we
 * assert the captured messages report the correct total (M = 3) and a running processed count.
 *
 * The OCAL headless `renameFile`/`onCleanCache` wall was fixed in obsidian-integration-testing
 * 9.1.1 (which this plugin now uses), so this runs headlessly. The rename promise is still bounded with
 * a race + effect-poll (mirroring the sibling rename suites) so a lingering `onCleanCache` wait cannot
 * hang the test.
 */

interface OperationQueueWrapper {
  readonly value?: OperationQueueState;
}

/*
 * Desktop-only: no Android emulator is available in this environment. The rename/link-update flow is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to
 * Android once an emulator exists.
 */

describe('Link-update progress notification (issue #25)', () => {
  it('shows an "Updating links: N/M" progress notice while a renamed file\'s backlinks are updated', async () => {
    const SOURCE_COUNT = 3;
    const result = await evalInObsidian({
      async callback({ app, lib: { waitUntil }, sourceCount }): Promise<LinkUpdateProgressResult> {
        const QUEUE_DRAIN_POLL_IN_MILLISECONDS = 100;
        const QUEUE_DRAIN_TIMEOUT_IN_MILLISECONDS = 15_000;

        interface RenameSettings {
          attachmentFolderPath: string;
          shouldHandleRenames: boolean;
        }

        function isRenameSettings(value: unknown): value is RenameSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldHandleRenames'] === 'boolean'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        // The plugin does not expose its settings publicly, so locate the live settings object by
        // Walking the plugin's component tree (same approach as the other OCAL integration tests).
        function findSettings(): null | RenameSettings {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [app.plugins.getPlugin('obsidian-custom-attachment-location')];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            if (isRenameSettings(record['settings'])) {
              return record['settings'];
            }
            let values: unknown[] = [];
            if (Array.isArray(current)) {
              values = current;
            } else if (current instanceof Map) {
              values = [...current.values()];
            } else {
              for (const [key, value] of Object.entries(record)) {
                if (!block.has(key)) {
                  values.push(value);
                }
              }
            }
            for (const value of values) {
              if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
                queue.push(value);
              }
            }
          }
          return null;
        }

        const settings = findSettings();
        if (!settings) {
          return { allNoticeTexts: [], capturedMessages: [], lingeringProgressNoticeCount: 0, settingsFound: false, sourceCount, sourceRewritten: false, targetRenamed: false };
        }

        settings.shouldHandleRenames = true;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folder = `progress-${stamp}`;
        await app.vault.createFolder(folder);
        const target = await app.vault.create(`${folder}/target.md`, '');
        const sources: (typeof target)[] = [];
        for (let index = 0; index < sourceCount; index++) {
          const src = await app.vault.create(`${folder}/src-${index.toString()}.md`, `See [[${folder}/target]].`);
          sources.push(src);
        }

        // Wait for the metadata cache to resolve every backlink so the rename handler updates them all.
        await waitUntil({
          message: 'all backlinks to the target resolve',
          predicate: () => app.metadataCache.getBacklinksForFile(target).keys().length >= sourceCount,
          timeoutInMilliseconds: 40_000
        });

        const [firstSource] = sources;
        if (!firstSource) {
          return { allNoticeTexts: [], capturedMessages: [], lingeringProgressNoticeCount: 0, settingsFound: true, sourceCount, sourceRewritten: false, targetRenamed: false };
        }
        const before = await app.vault.read(firstSource);

        // Collect every "Updating links: N/M" notice text mutated into the DOM during the rename.
        const captured = new Set<string>();
        const allNotices = new Set<string>();
        function collect(): void {
          for (const el of document.querySelectorAll('.notice')) {
            const text = el.textContent;
            allNotices.add(text);
            if (text.includes('Updating links:')) {
              captured.add(text);
            }
          }
        }
        /*
         * `collect` re-queries the LIVE DOM, so it only ever sees notices that are still on screen.
         * With three backlinks the pass can finish inside one observer batch — the notice is added and
         * dismissed before the callback runs — and the live DOM is then already empty, which is how
         * this suite intermittently captured nothing at all. The mutation records still hold the node,
         * so reading them catches a notice that has since been removed.
         */
        function considerText(text: string): void {
          if (text !== '') {
            allNotices.add(text);
          }
          if (text.includes('Updating links:')) {
            captured.add(text);
          }
        }
        function collectFromNode(node: Node): void {
          const el = node.instanceOf(HTMLElement) ? node : node.parentElement;
          considerText(el?.closest('.notice')?.textContent ?? '');
          // The notice can also arrive inside a freshly appended container rather than as the node.
          for (const noticeEl of el?.querySelectorAll('.notice') ?? []) {
            considerText(noticeEl.textContent);
          }
        }
        const observer = new MutationObserver((mutations) => {
          for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
              collectFromNode(node);
            }
            collectFromNode(mutation.target);
          }
          collect();
        });
        observer.observe(document.body, { characterData: true, childList: true, subtree: true });

        function countLingeringProgressNotices(): number {
          return [...document.querySelectorAll('.notice')].filter((el) => el.textContent.includes('Updating links:')).length;
        }

        async function areAllSourcesRewritten(): Promise<boolean> {
          for (const src of sources) {
            const content = await app.vault.read(src);
            if (!content.includes('renamed')) {
              return false;
            }
          }
          return true;
        }

        /*
         * Creating the target and its source notes queues the plugin's own create handling on
         * obsidian-dev-utils' GLOBAL operation queue, which runs one entry at a time. Renaming while
         * those are still draining means the plugin's rename handling — and with it the progress
         * reporter this suite exists to observe — starts late or not at all, while Obsidian's own
         * `alwaysUpdateLinks` rewrites the links anyway. That combination is exactly the observed
         * failure: every link correctly updated, and not a single notice on screen.
         */
        async function waitForQueueToDrain(): Promise<void> {
          const queueState = (window as ObsidianDevUtilsGlobal).__obsidianDevUtils?.['queue']?.value;
          const queueDeadline = Date.now() + QUEUE_DRAIN_TIMEOUT_IN_MILLISECONDS;
          while ((queueState?.items?.length ?? 0) > 0 && Date.now() < queueDeadline) {
            await sleep(QUEUE_DRAIN_POLL_IN_MILLISECONDS);
          }
        }
        await waitForQueueToDrain();

        try {
          // `renameFile`'s promise can linger on `metadataCache.onCleanCache`; bound it and poll the
          // Observable effect (the source notes rewritten to the new target name) as the settle signal.
          const renamePromise = app.fileManager.renameFile(target, `${folder}/renamed.md`);
          await Promise.race([
            renamePromise.catch(() => {
              // Lingering `onCleanCache`; the effect is polled below.
            }),
            sleep(6000)
          ]);

          // Wait until EVERY backlink source note is rewritten, so the whole link-update pass has run.
          await waitUntil({
            message: 'all source backlinks are rewritten after the rename',
            predicate: async () => {
              collect();
              return areAllSourcesRewritten();
            },
            timeoutInMilliseconds: 40_000
          });

          // The reporter dismisses the notice on completion, so it must clear once the pass finishes.
          await waitUntil({
            message: 'the progress notice is dismissed once the link update completes',
            predicate: () => {
              collect();
              return countLingeringProgressNotices() === 0;
            },
            timeoutInMilliseconds: 40_000
          });
        } finally {
          observer.disconnect();
        }

        const isTargetRenamed = Boolean(app.vault.getFileByPath(`${folder}/renamed.md`));
        const isSourceRewritten = (await app.vault.read(firstSource)) !== before;
        const lingeringProgressNoticeCount = countLingeringProgressNotices();

        return { allNoticeTexts: [...allNotices], capturedMessages: [...captured], lingeringProgressNoticeCount, settingsFound: true, sourceCount, sourceRewritten: isSourceRewritten, targetRenamed: isTargetRenamed };
      },
      input: { sourceCount: SOURCE_COUNT },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.targetRenamed).toBe(true);
    expect(result.sourceRewritten).toBe(true);

    // The progress reporter fired: at least one "Updating links: N/M" notice reached the DOM. The
    // Message carries every notice seen, so a miss says whether ANYTHING was shown.
    expect(
      result.capturedMessages.length,
      `no "Updating links:" notice; all notices seen: ${JSON.stringify(result.allNoticeTexts)}`
    ).toBeGreaterThan(0);

    const progressPairs = result.capturedMessages
      .map((message) => /Updating links: (?<processed>\d+)\/(?<total>\d+)/.exec(message))
      .filter((match): match is RegExpExecArray => match !== null)
      .map((match) => ({ processed: Number(match.groups?.['processed']), total: Number(match.groups?.['total']) }));

    expect(progressPairs.length).toBeGreaterThan(0);

    // Every message reports the correct total M (the number of backlink source notes).
    for (const pair of progressPairs) {
      expect(pair.total).toBe(result.sourceCount);
      expect(pair.processed).toBeGreaterThanOrEqual(1);
      expect(pair.processed).toBeLessThanOrEqual(pair.total);
    }

    /*
     * The running count advances across the backlink source files (at least two distinct processed
     * values, reaching the penultimate file). The FINAL "M/M" tick is set and the notice hidden in
     * the same synchronous callback (completion dismisses it), so it is not reliably observable via
     * the async MutationObserver — the dismissal itself is asserted below via the lingering count.
     */
    const distinctProcessed = new Set(progressPairs.map((pair) => pair.processed));
    expect(distinctProcessed.size).toBeGreaterThanOrEqual(2);
    const maxProcessed = Math.max(...progressPairs.map((pair) => pair.processed));
    expect(maxProcessed).toBeGreaterThanOrEqual(result.sourceCount - 1);

    // The notice is cleared once the update completes (nothing lingers to confuse the user).
    expect(result.lingeringProgressNoticeCount).toBe(0);
  }, 120_000);
});
