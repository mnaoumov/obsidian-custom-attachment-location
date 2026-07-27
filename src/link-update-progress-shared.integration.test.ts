import { evalInObsidian } from 'obsidian-integration-testing';
import { getTempVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

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

interface LinkUpdateProgressResult {
  readonly capturedMessages: readonly string[];
  readonly lingeringProgressNoticeCount: number;
  readonly settingsFound: boolean;
  readonly sourceCount: number;
  readonly sourceRewritten: boolean;
  readonly targetRenamed: boolean;
}

export function registerLinkUpdateProgressSuite(platform: string): void {
  describe(`Link-update progress notification (issue #25) [${platform}]`, () => {
    it('shows an "Updating links: N/M" progress notice while a renamed file\'s backlinks are updated', async () => {
      const SOURCE_COUNT = 3;
      const result = await evalInObsidian({
        args: { sourceCount: SOURCE_COUNT },
        async fn({ app, lib: { waitUntil }, sourceCount }): Promise<LinkUpdateProgressResult> {
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
                values = Array.from(current.values());
              } else {
                for (const key of Object.keys(record)) {
                  if (!block.has(key)) {
                    values.push(record[key]);
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
            return { capturedMessages: [], lingeringProgressNoticeCount: 0, settingsFound: false, sourceCount, sourceRewritten: false, targetRenamed: false };
          }

          settings.shouldHandleRenames = true;

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const folder = `progress-${stamp}`;
          await app.vault.createFolder(folder);
          const target = await app.vault.create(`${folder}/target.md`, '');
          const sources: (typeof target)[] = [];
          for (let i = 0; i < sourceCount; i++) {
            const src = await app.vault.create(`${folder}/src-${i.toString()}.md`, `See [[${folder}/target]].`);
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
            return { capturedMessages: [], lingeringProgressNoticeCount: 0, settingsFound: true, sourceCount, sourceRewritten: false, targetRenamed: false };
          }
          const before = await app.vault.read(firstSource);

          // Collect every "Updating links: N/M" notice text mutated into the DOM during the rename.
          const captured = new Set<string>();
          function collect(): void {
            for (const el of Array.from(document.querySelectorAll('.notice'))) {
              const text = el.textContent;
              if (text.includes('Updating links:')) {
                captured.add(text);
              }
            }
          }
          const observer = new MutationObserver(() => {
            collect();
          });
          observer.observe(document.body, { characterData: true, childList: true, subtree: true });

          function countLingeringProgressNotices(): number {
            return Array.from(document.querySelectorAll('.notice')).filter((el) => el.textContent.includes('Updating links:')).length;
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

          try {
            // `renameFile`'s promise can linger on `metadataCache.onCleanCache`; bound it and poll the
            // Observable effect (the source notes rewritten to the new target name) as the settle signal.
            const renamePromise = app.fileManager.renameFile(target, `${folder}/renamed.md`);
            await Promise.race([
              renamePromise.catch(() => {
                // Lingering `onCleanCache`; the effect is polled below.
              }),
              sleep(6_000)
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

          const targetRenamed = Boolean(app.vault.getFileByPath(`${folder}/renamed.md`));
          const sourceRewritten = (await app.vault.read(firstSource)) !== before;
          const lingeringProgressNoticeCount = countLingeringProgressNotices();

          return { capturedMessages: Array.from(captured), lingeringProgressNoticeCount, settingsFound: true, sourceCount, sourceRewritten, targetRenamed };
        },
        vaultPath: getTempVault().path
      });

      expect(result.settingsFound).toBe(true);
      expect(result.targetRenamed).toBe(true);
      expect(result.sourceRewritten).toBe(true);

      // The progress reporter fired: at least one "Updating links: N/M" notice reached the DOM.
      expect(result.capturedMessages.length).toBeGreaterThan(0);

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
}
