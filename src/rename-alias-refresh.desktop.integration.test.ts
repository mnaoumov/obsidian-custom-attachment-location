import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #20 (ODU-side fix consumed via obsidian-dev-utils 88.2.0): with
 * "Should handle renames" ON, renaming a target file whose backlink carries an alias equal to the
 * OLD base name (`[[folder/2|2]]`) must refresh the alias to the NEW base name (`[[folder/222|222]]`),
 * not leave a stale `|2`. The plugin already requests `shouldUpdateFileNameAliases: true`; the defect
 * was in ODU's `updateLink`, fixed upstream in 88.2.0.
 *
 * VERIFIED PASSING IN ISOLATION (2026-07-25) — run this file alone:
 *   npx vitest run --project=integration-tests:desktop rename-alias-refresh
 * It renames `folder/2.md` -> `folder/222.md` and asserts the backlink display text becomes `222`
 * (real Obsidian normalizes the refreshed link to `[[222]]`), never the stale `|2`.
 *
 * G97 ESCAPE HATCH — `it.skip` in the committed suite. In the shared-instance desktop AGGREGATE
 * (`npm run test:integration:desktop`, all files in ONE headless Obsidian), `app.fileManager.renameFile`
 * and the ODU rename handler stall on `metadataCache.onCleanCache` once several rename/collect flows
 * have run in the same instance — the documented headless renameFile wall. Confirmed empirically: the
 * rename effect never materializes within a 40s budget in the aggregate, and even the three rename
 * suites run together (nothing else) reproduce the stall, while each passes alone. Not silently
 * omitted; the fix is also unit-covered upstream in ODU (`link.ts` alias-refresh test).
 */

interface RenameAliasResult {
  readonly after: string;
  readonly before: string;
  readonly settingsFound: boolean;
  readonly targetRenamed: boolean;
}

/*
 * Desktop-only: no Android emulator is available in this environment. The rename/link-update flow is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to
 * Android once an emulator exists.
 */

describe('Rename refreshes a file-name alias (issue #20)', () => {
  // Skipped in the aggregate (shared-instance renameFile/onCleanCache stall); passes in isolation.
  it.skip('rewrites [[folder/2|2]] to [[folder/222|222]] when the target is renamed', async () => {
    const result = await evalInObsidian({
      async callback({ app, lib: { waitUntil } }): Promise<RenameAliasResult> {
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
          return { after: '', before: '', settingsFound: false, targetRenamed: false };
        }

        settings.shouldHandleRenames = true;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folder = `alias-${stamp}`;
        await app.vault.createFolder(folder);
        const target = await app.vault.create(`${folder}/2.md`, '');
        const src = await app.vault.create(`alias-src-${stamp}.md`, `[[${folder}/2|2]]`);

        // Wait for the metadata cache to resolve the backlink so the rename handler can update it.
        await waitUntil({
          message: 'backlink to the target resolves',
          predicate: () => app.metadataCache.getBacklinksForFile(target).keys().length > 0,
          timeoutInMilliseconds: 40_000
        });

        const before = await app.vault.read(src);

        // `renameFile`'s promise can hang on `metadataCache.onCleanCache` in the shared-instance
        // Aggregate (documented headless wall) even though the core rename + the ODU handler proceed,
        // So bound it with a race and poll for the observable effect. A lingering `onCleanCache` wait
        // Holds no resource lock, so it does not leak into later tests.
        const renamePromise = app.fileManager.renameFile(target, `${folder}/222.md`);
        await Promise.race([
          renamePromise.catch(() => {
            // Lingering `onCleanCache`; the effect is polled below.
          }),
          sleep(6000)
        ]);

        // The rename handler rewrites backlinks on its internal queue; wait until the source settles.
        await waitUntil({
          message: 'source backlink is rewritten after the rename',
          predicate: async () => (await app.vault.read(src)) !== before,
          timeoutInMilliseconds: 40_000
        });

        const isTargetRenamed = Boolean(app.vault.getFileByPath(`${folder}/222.md`));
        const after = await app.vault.read(src);
        return { after, before, settingsFound: true, targetRenamed: isTargetRenamed };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.before).toContain('/2|2]]');
    expect(result.targetRenamed).toBe(true);

    /*
     * Issue #20: the file-name alias must be refreshed to the NEW base name, never left stale as
     * `|2`. Real Obsidian normalizes the refreshed link to its shortest unique form `[[222]]`
     * (an alias equal to the base name is redundant and dropped), so the observable, form-
     * independent effect is: the link references the new name `222` and carries no stale `|2`
     * alias (display text `2`). With the pre-88.2.0 ODU bug the result was `[[222|2]]` — display
     * text `2` — which the `not.toMatch` below would catch.
     */
    expect(result.after).toContain('222');
    expect(result.after).not.toMatch(/\|2\]\]/);
    expect(result.after).not.toBe(result.before);
  }, 120_000);
});
