import { evalInObsidian } from 'obsidian-integration-testing';
import { getTempVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #45 (ODU-side fix consumed via obsidian-dev-utils 88.2.0): with
 * "Should handle renames" ON, ODU's rename flow must NOT write a malformed/partial `.canvas` (one
 * whose parsed JSON lacks `nodes`/`edges` arrays) back to disk. Advanced Canvas transiently leaves a
 * freshly inserted canvas as `{}` / partial while it initializes; pre-88.2.0 `applyCanvasChanges`
 * re-serialized that malformed object back, and Obsidian's canvas renderer then threw
 * `Cannot read properties of undefined (reading 'length')` / `data.edges is not iterable`. 88.2.0
 * adds the symmetric guard: `applyCanvasChanges` returns null (skips the write) when
 * `nodes`/`edges` are not both arrays.
 *
 * G97 ESCAPE HATCH — the ODU guard cannot be isolated in the hidden-mode headless harness:
 *   - The exact Advanced Canvas mid-init race (a freshly inserted canvas transiently `{}`/partial
 *     while the plugin initializes it) cannot be synthesized without installing Advanced Canvas and
 *     hitting a timing window.
 *   - Reproducing the guarded path directly requires ODU (not Obsidian core) to be the one writing
 *     the canvas on malformed content. For a MOVE, Obsidian CORE rewrites canvas FILE-node
 *     references itself (confirmed empirically: moving a partial no-edges canvas with a file-node
 *     attachment relocates the attachment AND core rewrites the file node, tab-serialized, without
 *     crashing — ODU's `applyCanvasChanges` is never the actor). ODU-driven canvas writes are for
 *     TEXT-node embeds / file-node COPIES, and text-node embed discovery does not populate headlessly
 *     (see the issue-#27 suite), so there is no OCAL flow that routes malformed canvas content
 *     through ODU `applyCanvasChanges` here.
 *
 * The guard IS covered upstream by ODU unit tests (obsidian-dev-utils `file-change.test.ts`: `{}`,
 * partial `{"nodes":[...]}` with no `edges` -> `applyCanvasChanges` returns null / skips the write).
 * The smoke test below is an honest end-to-end check of the fix's INTENT: OCAL's rename handler, with
 * "Should handle renames" ON, over a partial (no-edges) canvas completes without throwing, still
 * relocates the embedded attachment, and leaves the canvas as valid, parseable canvas JSON (never
 * corrupted). It PASSES IN ISOLATION but is `it.skip` in the committed aggregate because it renames a
 * file and hits the same shared-instance `renameFile`/`onCleanCache` stall as the issue-#20/#22 suites
 * (run it alone: `npx vitest run --project=integration-tests:desktop canvas-non-canvas-guard`). The
 * Advanced-Canvas-specific crash-prevention is a separate documented, skipped test with the manual
 * recipe below.
 *
 * MANUAL REPRO (real Obsidian, GUI):
 *   1. Install + enable Custom Attachment Location and Advanced Canvas; "Should handle renames" ON.
 *   2. Use Advanced Canvas to insert a new canvas (its "create canvas" affordance).
 *   3. Pre-88.2.0: the insert throws `Cannot read properties of undefined (reading 'length')` /
 *      `data.edges is not iterable` (ODU re-serialized the transient `{}` canvas). With 88.2.0 the
 *      guard skips that write and the canvas inserts cleanly. Disabling "Should handle renames" also
 *      avoids the error (it stops ODU from writing the canvas), which is the diagnostic tell.
 */

interface CanvasGuardResult {
  readonly canvasHasNodesArrayAfter: boolean;
  readonly canvasParsesAfter: boolean;
  readonly imgAtNewPath: boolean;
  readonly imgAtOldPath: boolean;
  readonly settingsFound: boolean;
}

interface CanvasNodesProbe {
  nodes?: unknown;
}

/*
 * Desktop-only: no Android emulator is available in this environment. The canvas guard is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to
 * Android once an emulator exists.
 */

describe('Rename over a partial canvas is safe (issue #45)', () => {
  // Skipped in the aggregate (shared-instance renameFile/onCleanCache stall); passes in isolation.
  // Run alone: npx vitest run --project=integration-tests:desktop canvas-non-canvas-guard
  it.skip('completes without crashing, relocates the attachment, and keeps the canvas valid', async () => {
    const result = await evalInObsidian({
      args: {},
      async fn({ app }): Promise<CanvasGuardResult> {
        interface CanvasSettings {
          attachmentFolderPath: string;
          shouldHandleRenames: boolean;
          shouldRenameAttachmentFolder: boolean;
        }

        function isCanvasSettings(value: unknown): value is CanvasSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldHandleRenames'] === 'boolean'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string'
            && typeof (value as Record<string, unknown>)['shouldRenameAttachmentFolder'] === 'boolean';
        }

        function findSettings(): CanvasSettings | null {
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
            if (isCanvasSettings(record['settings'])) {
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
          return { canvasHasNodesArrayAfter: false, canvasParsesAfter: false, imgAtNewPath: false, imgAtOldPath: true, settingsFound: false };
        }

        settings.shouldHandleRenames = true;
        settings.shouldRenameAttachmentFolder = true;
        settings.attachmentFolderPath = './assets';

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folderA = `guardA-${stamp}`;
        const folderB = `guardB-${stamp}`;
        await app.vault.createFolder(folderA);
        await app.vault.createFolder(folderB);
        await app.vault.createFolder(`${folderA}/assets`);

        const imgOldPath = `${folderA}/assets/img-${stamp}.png`;
        const imgNewPath = `${folderB}/assets/img-${stamp}.png`;
        await app.vault.createBinary(imgOldPath, new ArrayBuffer(4));

        // Partial canvas: a nodes array but NO edges array — the exact malformed shape the guard
        // Protects (Advanced Canvas leaves this transiently while initializing a fresh canvas).
        const malformedCanvas = `{\n  "nodes": [\n    { "id": "node1", "type": "file", "file": "${imgOldPath}", "x": 0, "y": 0, "width": 400, "height": 300 }\n  ]\n}`;
        const canvas = await app.vault.create(`${folderA}/board-${stamp}.canvas`, malformedCanvas);
        await sleep(500);

        const movedCanvasPath = `${folderB}/board-${stamp}.canvas`;
        // `renameFile`'s promise can hang on `metadataCache.onCleanCache` in the shared-instance
        // Aggregate (documented headless wall) even though the core rename + the ODU handler proceed,
        // So bound it with a race and poll for the observable effect. A lingering `onCleanCache` wait
        // Holds no resource lock, so it does not leak into later tests.
        const renamePromise = app.fileManager.renameFile(canvas, movedCanvasPath);
        await Promise.race([
          renamePromise.catch(() => {
            // Lingering `onCleanCache`; the effect is polled below.
          }),
          sleep(6_000)
        ]);

        // Poll until the attachment relocates (proves ODU processed the canvas).
        const deadline = Date.now() + 40_000;
        while (Date.now() < deadline) {
          if (app.vault.getFileByPath(imgNewPath) && !app.vault.getFileByPath(imgOldPath)) {
            break;
          }
          await sleep(300);
        }
        // Let any canvas rewrite settle, then confirm the canvas is still valid (not corrupted).
        await sleep(1_000);

        const movedCanvas = app.vault.getFileByPath(movedCanvasPath);
        const canvasContentAfter = movedCanvas ? await app.vault.read(movedCanvas) : '';
        let canvasParsesAfter = false;
        let canvasHasNodesArrayAfter = false;
        try {
          const parsed = JSON.parse(canvasContentAfter) as CanvasNodesProbe;
          canvasParsesAfter = true;
          canvasHasNodesArrayAfter = Array.isArray(parsed.nodes);
        } catch {
          // Left corrupted / unparseable — canvasParsesAfter stays false.
        }

        return {
          canvasHasNodesArrayAfter,
          canvasParsesAfter,
          imgAtNewPath: Boolean(app.vault.getFileByPath(imgNewPath)),
          imgAtOldPath: Boolean(app.vault.getFileByPath(imgOldPath)),
          settingsFound: true
        };
      },
      vaultPath: getTempVault().path
    });

    expect(result.settingsFound).toBe(true);

    // The rename over the partial canvas completed and still relocated the embedded attachment.
    expect(result.imgAtNewPath).toBe(true);
    expect(result.imgAtOldPath).toBe(false);

    // Issue #45 (fix intent): the partial canvas is NOT corrupted by OCAL's rename handler — it
    // Remains valid, parseable canvas JSON with a nodes array. Pre-88.2.0 ODU could re-serialize a
    // Malformed canvas into a shape its renderer chokes on; 88.2.0 guards `applyCanvasChanges`.
    expect(result.canvasParsesAfter).toBe(true);
    expect(result.canvasHasNodesArrayAfter).toBe(true);
  }, 120_000);

  /*
   * The ODU-guard-specific isolation (proving `applyCanvasChanges` SKIPS the write on malformed
   * content, rather than Obsidian core doing a valid file-node rewrite) needs the Advanced Canvas
   * transient-`{}` insert race — see the G97 escape-hatch note + manual recipe above. Skipped, not
   * silently omitted; the guard itself is unit-covered upstream in ODU `file-change.test.ts`.
   */
  it.skip('skips the ODU canvas write on transient `{}` from Advanced Canvas (needs the Advanced Canvas plugin + insert race)', () => {
    // Intentionally empty: verified by the ODU unit test and the manual recipe above.
  });
});
