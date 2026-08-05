import { evalInObsidian } from 'obsidian-integration-testing';
import { getTempVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #49 ("Attachments get renamed when Advanced Note Composer swaps two
 * folders"): a rename performed inside ANOTHER plugin's locked transaction must be left alone. The
 * plugin is a bystander there - the transaction's owner moves the files and keeps its own links
 * consistent - so reacting to those renames corrupts them.
 *
 * The reporter's recording swaps folder `B` with its own parent `A` via Advanced Note Composer's
 * `Swap folder with...`, and both notes come back de-duplicated: `A/Overview.md` and
 * `A/B/Overview.md` end up as `B/A/Overview 1.md` and `B/Overview 1.md`, so every link to them
 * dangles. The de-duplication is the fingerprint: ANC renames through `renameSafe`, which asks
 * `getAvailablePath` for another name whenever the destination is occupied - and the destination is
 * only ever "occupied" because the rename handler re-registers a phantom `TFile` at the OLD path
 * (`RenameHandler.refreshLinks`, tracked as T331-P1) while ANC's next rename is picking a name.
 *
 * ANC 5.3.0 (the reporter's version) DOES take `subtree` locks on both folders for the whole swap,
 * and ODU's handler DOES skip a rename covered by such a lock
 * (`rename-delete-handler-component.ts`, `handleRename`). The guard misses here because the lock
 * registry is path-keyed (`ResourceLockManager.lockEntriesByPath`) and nothing re-keys it when a
 * locked folder is itself renamed - which is the first thing a folder swap does. After
 * `A/B` -> `A/A` and `A` -> `B`, the live tree is `B/...` while the lock keys still read `A` and
 * `A/B`, so every subsequent child move looks unlocked and the handler joins in.
 *
 * This suite reproduces that without installing a second plugin: it takes the same `subtree` locks
 * through ODU's realm-global lock manager (`globalThis.__obsidianDevUtils`, shared by every plugin
 * that bundles the library, which is exactly how the guard sees ANC's locks) under a foreign plugin
 * id, then replays ANC's `swapFolder` sequence verbatim.
 *
 * It pins BOTH halves:
 *   - the symptom - no note may come back with a de-duplicated ` 1` name;
 *   - the mechanism - every rename of the swap must be reported as lock-covered, so a failure names
 *     the hole instead of just the damage;
 * and runs a control phase first, with the rename handler switched off, to show that the replayed
 * sequence is sound on its own - the damage belongs to the handler, not to Advanced Note Composer.
 *
 * This suite REPRODUCED the defect headlessly against obsidian-dev-utils 88.8.0 / Obsidian 1.13.4
 * (verified 2026-08-02): the control phase was clean while the reporter phase reported all three file
 * moves as unlocked and landed `B/A/Overview 1.md` - the reporter's own damage. It was committed
 * `it.skip` while the upstream fixes were pending (T332-P1: re-key `lockEntriesByPath` when a locked
 * folder is renamed; T331-P1: remove the phantom old-path registration that supplies the
 * de-duplication), and un-skipped once obsidian-dev-utils 89.0.0 shipped both.
 *
 * Run it with:
 *   npx vitest run --project=integration-tests:desktop foreign-locked-folder-swap
 *
 * Desktop-only: no Android emulator is provisioned in this environment. The rename/lock flow is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to
 * Android once an emulator exists.
 */

interface PhaseResult {
  readonly finalPaths: readonly string[];
  readonly steps: readonly RenameStep[];
}

interface RenameStep {
  readonly actualNewPath: string;
  readonly oldPath: string;
  readonly requestedNewPath: string;
  readonly wasCoveredByLock: boolean;
}

interface SwapResult {
  readonly control: PhaseResult;
  readonly lockManagerFound: boolean;
  readonly reporter: PhaseResult;
  readonly settingsFound: boolean;
}

describe('A folder swap owned by another plugin (issue #49)', () => {
  it('leaves every rename of the locked transaction untouched', async () => {
    const result = await evalInObsidian({
      // eslint-disable-next-line unicorn/name-replacements -- `args` is an `obsidian-integration-testing` parameter name.
      args: {},
      // eslint-disable-next-line unicorn/name-replacements -- `fn` is an `obsidian-integration-testing` parameter name.
      async fn({ app, lib: { waitUntil } }): Promise<SwapResult> {
        interface LockDisposable {
          dispose(): void;
        }

        interface LockManager {
          isLockedByAncestor(app: unknown, pathOrFile: string): boolean;
          lock(params: LockParams): LockDisposable;
        }

        interface LockParams {
          readonly app: unknown;
          readonly mode: string;
          readonly operationName: string;
          readonly pathOrFile: string;
          readonly pluginId: string;
        }

        interface RenameSettings {
          shouldHandleRenames: boolean;
          shouldRenameAttachmentFiles: boolean;
          shouldRenameAttachmentFolder: boolean;
        }

        const EMPTY_PHASE: PhaseResult = { finalPaths: [], steps: [] };

        const settingsOrNull = findSettings();
        if (!settingsOrNull) {
          return { control: EMPTY_PHASE, lockManagerFound: false, reporter: EMPTY_PHASE, settingsFound: false };
        }

        const lockManagerOrNull = findLockManager();
        if (!lockManagerOrNull) {
          return { control: EMPTY_PHASE, lockManagerFound: false, reporter: EMPTY_PHASE, settingsFound: true };
        }

        // Re-bound as non-nullable consts: the inner functions below cannot see the narrowing above.
        const settings = settingsOrNull;
        const lockManager = lockManagerOrNull;

        const originalSettings: RenameSettings = {
          shouldHandleRenames: settings.shouldHandleRenames,
          shouldRenameAttachmentFiles: settings.shouldRenameAttachmentFiles,
          shouldRenameAttachmentFolder: settings.shouldRenameAttachmentFolder
        };
        const originalAlwaysUpdateLinks = app.vault.getConfig('alwaysUpdateLinks');

        let steps: RenameStep[] = [];

        try {
          // Matches the sample vault's `app.json`; without it Obsidian asks for confirmation via a
          // Modal instead of updating links, which would stall a headless run.
          app.vault.setConfig('alwaysUpdateLinks', true);

          /*
           * Control: the rename handler is switched off entirely (`handleRename` returns before it
           * queues anything), so the same sequence runs with nobody but the transaction touching the
           * files. It isolates the damage to the handler instead of to the sequence itself.
           */
          const control = await runPhase(false);
          const reporter = await runPhase(true);
          return { control, lockManagerFound: true, reporter, settingsFound: true };
        } finally {
          assignRenameSettings(settings, originalSettings);
          app.vault.setConfig('alwaysUpdateLinks', originalAlwaysUpdateLinks);
        }

        /*
         * The reporter's `data.json`: the plugin steps back from link updating but still follows
         * notes with their attachments, so the rename handler runs on every note move. Switching all
         * three off makes `handleRename` return before it queues anything - the control phase.
         */
        function applyPhaseSettings(phaseSettings: RenameSettings, isRenameHandlerEnabled: boolean): void {
          assignRenameSettings(phaseSettings, {
            shouldHandleRenames: false,
            shouldRenameAttachmentFiles: isRenameHandlerEnabled,
            shouldRenameAttachmentFolder: false
          });
        }

        function assignRenameSettings(target: RenameSettings, source: RenameSettings): void {
          target.shouldHandleRenames = source.shouldHandleRenames;
          target.shouldRenameAttachmentFiles = source.shouldRenameAttachmentFiles;
          target.shouldRenameAttachmentFolder = source.shouldRenameAttachmentFolder;
        }

        function findLockManager(): LockManager | null {
          /*
           * The manager is created lazily by the first lock operation, so nothing has put it on the
           * shared bag yet in a fresh vault. Ask the plugin's own lock component a harmless question
           * to force it into existence, then read the bag - the same instance every plugin sees.
           */
          const pluginValue: unknown = app.plugins.getPlugin('obsidian-custom-attachment-location');
          const lockComponent = readProperty(pluginValue, 'resourceLockComponent');
          const isLockedForPath = readProperty(lockComponent, 'isLockedForPath');
          if (typeof isLockedForPath === 'function') {
            (isLockedForPath as (this: unknown, pathOrFile: string) => boolean).call(lockComponent, '/');
          }

          // ODU keeps the bag on the realm global of the main renderer, which is this `window`.
          const managerValue = readProperty(readProperty(readProperty(window, '__obsidianDevUtils'), 'resourceLock'), 'value');
          if (typeof managerValue !== 'object' || managerValue === null) {
            return null;
          }
          return managerValue as LockManager;
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

        function getAvailablePath(path: string): string {
          const lastSlashIndex = path.lastIndexOf('/');
          const name = path.slice(lastSlashIndex + 1);
          const lastDotIndex = name.lastIndexOf('.');
          if (lastDotIndex <= 0) {
            return app.vault.getAvailablePath(path, '');
          }
          return app.vault.getAvailablePath(path.slice(0, path.length - (name.length - lastDotIndex)), name.slice(lastDotIndex + 1));
        }

        function isRenameSettings(value: unknown): value is RenameSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldHandleRenames'] === 'boolean'
            && typeof (value as Record<string, unknown>)['shouldRenameAttachmentFiles'] === 'boolean'
            && typeof (value as Record<string, unknown>)['shouldRenameAttachmentFolder'] === 'boolean';
        }

        async function runPhase(isRenameHandlerEnabled: boolean): Promise<PhaseResult> {
          applyPhaseSettings(settings, isRenameHandlerEnabled);
          steps = [];

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const root = `swap-${stamp}`;

          // The reporter's tree: `A` holds a note plus the sub-folders that are swapped with it.
          await app.vault.createFolder(root);
          await app.vault.createFolder(`${root}/A`);
          await app.vault.createFolder(`${root}/A/B`);
          await app.vault.createFolder(`${root}/A/C`);
          await app.vault.create(`${root}/A/Overview.md`, `Test [[${root}/A/B/Overview|Overview]]\n`);
          await app.vault.create(`${root}/A/B/Overview.md`, `B [[${root}/A/Overview|Overview]]\n`);
          await app.vault.create(`${root}/A/C/Overview.md`, `C [[${root}/A/Overview|Overview]]\n`);

          // The handler reads the cache of the note being moved, so let it resolve before swapping.
          await waitUntil({
            message: 'the notes are indexed',
            predicate: () => app.metadataCache.getCache(`${root}/A/Overview.md`) !== null,
            timeoutInMilliseconds: 40_000
          });

          /*
           * ANC locks both folders for the whole transaction under its own plugin id. The guard only
           * asks the shared manager whether the path is covered, so a foreign id reproduces it
           * exactly - and keeps this suite free of a second installed plugin.
           */
          const lockHandles = [`${root}/A`, `${root}/A/B`].map((path) =>
            lockManager.lock({
              app,
              mode: 'subtree',
              operationName: 'Swap folders',
              pathOrFile: path,
              pluginId: 'advanced-note-composer'
            })
          );

          try {
            await swapFolder(`${root}/A/B`, `${root}/A`, `__temp-${stamp}`);
          } finally {
            for (const lockHandle of lockHandles) {
              lockHandle.dispose();
            }
          }

          // The handler runs on a queue of its own, so give its damage time to land before sampling.
          await sleep(5000);

          const finalPaths = app.vault.getFiles()
            .map((file) => file.path)
            .filter((path) => path.startsWith(`${root}/`))
            .map((path) => path.slice(root.length + 1))
            .sort();

          return { finalPaths, steps };
        }

        // Reads one property off an untyped object, so the walk into ODU's shared bag (and into the
        // Plugin's protected lock component) stays free of stacked type assertions.
        function readProperty(value: unknown, key: string): unknown {
          if (typeof value !== 'object' || value === null) {
            return undefined;
          }
          return (value as Record<string, unknown>)[key];
        }

        /*
         * `VaultTransaction.rename` -> `renameSafe`: rename onto the requested path, or onto a
         * de-duplicated one when it is occupied. Recording whether the lock covered the rename is
         * what turns a failure into a diagnosis.
         */
        async function renameSafe(oldPath: string, newPath: string): Promise<string> {
          const file = app.vault.getAbstractFileByPath(oldPath);
          if (!file) {
            return oldPath;
          }

          const wasCoveredByLock = lockManager.isLockedByAncestor(app, oldPath) || lockManager.isLockedByAncestor(app, newPath);
          const actualNewPath = app.vault.getAbstractFileByPath(newPath) ? getAvailablePath(newPath) : newPath;

          // `renameFile`'s promise can linger on `metadataCache.onCleanCache`; bound it and poll the
          // Observable effect instead (mirroring the sibling rename suites).
          await Promise.race([
            app.fileManager.renameFile(file, actualNewPath).catch(() => {
              // Lingering `onCleanCache`; the effect is polled below.
            }),
            sleep(10_000)
          ]);

          const deadline = Date.now() + 10_000;
          while (Date.now() < deadline && !app.vault.getAbstractFileByPath(actualNewPath)) {
            await sleep(100);
          }

          steps.push({ actualNewPath, oldPath, requestedNewPath: newPath, wasCoveredByLock });
          return actualNewPath;
        }

        /*
         * A verbatim replay of `swapper.ts` `swapFolder` from Advanced Note Composer 5.3.0, with
         * `shouldSwapEntireFolderStructure` off (the reporter's run: only the files change place,
         * the sub-folders travel with their renamed parent). The staging folder is stamped rather
         * than the literal `__temp` ANC picks, purely so parallel suites cannot collide; it sits at
         * the vault root and outside every lock either way.
         */
        async function swapFolder(sourceFolderPath: string, targetFolderPath: string, temporaryFolderPath: string): Promise<void> {
          const sourceFolder = app.vault.getFolderByPath(sourceFolderPath);
          const targetFolder = app.vault.getFolderByPath(targetFolderPath);
          if (!sourceFolder || !targetFolder) {
            return;
          }

          const sourceFolderName = sourceFolder.name;
          const targetFolderName = targetFolder.name;

          /*
           * ANC holds the live `TFolder` / `TFile` objects across the whole sequence, so every path
           * it passes is the CURRENT one - which matters here, where the target folder is the
           * source's own parent and renaming it moves the source too. Reading `.path` at call time
           * (rather than capturing strings up front) reproduces that faithfully; the two
           * `…WithSourceName` / `…WithTargetName` values below are the exception, because ANC does
           * compute those before the renames and they do go stale.
           */
          if (sourceFolderName !== targetFolderName) {
            const sourceFolderWithTargetName = joinPath(sourceFolder.parent?.path ?? '', targetFolderName);
            await renameSafe(sourceFolder.path, sourceFolderWithTargetName);
            const targetFolderWithSourceName = joinPath(targetFolder.parent?.path ?? '', sourceFolderName);
            await renameSafe(targetFolder.path, targetFolderWithSourceName);

            // Only the source folder can need a second rename: it lands on a de-duplicated name
            // While the target still occupies the slot, then retries once the target has vacated it.
            if (sourceFolder.name !== targetFolderName && !app.vault.getFolderByPath(sourceFolderWithTargetName)) {
              await renameSafe(sourceFolder.path, sourceFolderWithTargetName);
            }
          }

          await app.vault.createFolder(temporaryFolderPath);

          const sourceChildren = sourceFolder.children.flatMap((child) => app.vault.getFileByPath(child.path) ?? []);
          const targetChildren = targetFolder.children.flatMap((child) => app.vault.getFileByPath(child.path) ?? []);
          const stagedChildren: typeof sourceChildren = [];
          const targetFolderPathBeforeChildren = targetFolder.path;

          for (const sourceChild of sourceChildren) {
            await renameSafe(sourceChild.path, joinPath(temporaryFolderPath, sourceChild.name));
            stagedChildren.push(sourceChild);
          }

          for (const targetChild of targetChildren) {
            if (isChildPath(sourceFolder.path, targetChild.path)) {
              continue;
            }
            await renameSafe(targetChild.path, joinPath(sourceFolder.path, targetChild.name));
          }

          if (targetFolder.path !== targetFolderPathBeforeChildren) {
            await renameSafe(targetFolder.path, targetFolderPathBeforeChildren);
          }

          for (const stagedChild of stagedChildren) {
            if (!isChildPath(stagedChild.path, temporaryFolderPath)) {
              continue;
            }
            await renameSafe(stagedChild.path, joinPath(targetFolder.path, stagedChild.name));
          }

          const temporaryFolder = app.vault.getFolderByPath(temporaryFolderPath);
          if (temporaryFolder) {
            await app.fileManager.trashFile(temporaryFolder);
          }

          function isChildPath(childPath: string, parentPath: string): boolean {
            return childPath.startsWith(`${parentPath}/`);
          }

          function joinPath(parentPath: string, name: string): string {
            return parentPath === '' ? name : `${parentPath}/${name}`;
          }
        }
      },
      vaultPath: getTempVault().path
    });

    const expectedFinalPaths = ['B/A/Overview.md', 'B/C/Overview.md', 'B/Overview.md'];

    expect(result.settingsFound).toBe(true);
    expect(result.lockManagerFound).toBe(true);

    // Both phases really ran the whole replayed sequence: two folder renames plus three file moves.
    expect(result.control.steps).toHaveLength(5);
    expect(result.reporter.steps).toHaveLength(5);

    /*
     * Control: with the rename handler switched off, the very same sequence under the very same
     * locks lands every file exactly where it was asked to. So the sequence is sound and the damage
     * below belongs to the handler, not to Advanced Note Composer.
     */
    expect(result.control.steps.filter((step) => step.actualNewPath !== step.requestedNewPath)).toStrictEqual([]);
    expect(result.control.finalPaths).toStrictEqual(expectedFinalPaths);

    /*
     * The mechanism. Advanced Note Composer holds a `subtree` lock on both folders for the whole
     * transaction, so NO rename of that transaction may be seen as unlocked - the moment one is, the
     * handler stops skipping and joins in. The locks are path-keyed, so the folder renames that open
     * the swap move both folders out from under their own locks.
     */
    expect(result.reporter.steps.filter((step) => !step.wasCoveredByLock)).toStrictEqual([]);

    // Issue #49: nothing may be de-duplicated - a swap moves files, it does not rename them.
    expect(result.reporter.steps.filter((step) => step.actualNewPath !== step.requestedNewPath)).toStrictEqual([]);
    expect(result.reporter.finalPaths).toStrictEqual(expectedFinalPaths);
  }, 300_000);
});
