import { evalInObsidian } from 'obsidian-integration-testing';
import { getTempVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * Coverage for issue #27 (ODU-side fix consumed via obsidian-dev-utils 88.2.0): a canvas text node
 * holding a markdown TABLE cell with a sized, table-escaped embed `![[img.png\|500]]` must keep the
 * `\|500` escaping (embed size) when the canvas rewrite retargets the embed. Pre-88.2.0 the rewrite
 * emitted an UNescaped `|500`, breaking the surrounding table. The fix lives in ODU
 * `applyCanvasChanges`, which restores the escaping when the original reference used `\|`.
 *
 * G97 ESCAPE HATCH — the behavioral rewrite cannot be driven to completion in the hidden-mode
 * headless harness. Confirmed empirically against the harness-owned real Obsidian:
 *   - Renaming the IMAGE directly does not reach canvas text-node embeds (canvases are not in the
 *     backlink cache; ODU's rename handler invokes `getCanvasReferences` only when the RENAMED file
 *     is itself a canvas).
 *   - Moving the CANVAS relocates FILE-node attachments (the issue-#22 suite passes) but NOT a
 *     TEXT-node embed's attachment.
 *   - "Collect attachments in current note" over the canvas (canvas confirmed as the active file,
 *     command executed) does NOT relocate/rewrite the embed — for BOTH a plain `![[img.png]]` and
 *     the table-escaped `![[img.png\|500]]`. Root cause: `getCanvasReferences` discovers canvas
 *     FILE-node references headlessly (proven by the issue-#22 suite) but NOT TEXT-node embeds,
 *     because canvas text-node markdown parsing (`computeMetadataAsync`) does not populate in the
 *     hidden-mode harness. With no text-node reference discovered, no flow reaches
 *     `applyCanvasChanges` for a text embed, so the escaping fix cannot be observed here.
 *
 * The fix IS covered upstream by an ODU unit test (obsidian-dev-utils `file-change.test.ts`: a
 * round-trip of a table-escaped sized embed `![[old.png\|500]]` -> `![[new.png\|500]]`). This suite
 * is therefore recorded as a documented, skipped behavioral test with the assertions it WOULD run
 * plus the manual repro recipe below, rather than silently omitted (G97).
 *
 * MANUAL REPRO (real Obsidian, GUI):
 *   1. Install + enable Custom Attachment Location; set "Location for new attachments" to a relative
 *      shared folder (e.g. `./assets`), "Should handle renames" ON.
 *   2. Create `img.png` and a canvas containing a TEXT card with a markdown table whose cell is
 *      `| ![[img.png\|500]] |`. Save.
 *   3. Rename `img.png` -> `renamed.png` (or run "Collect attachments in current note" on the canvas).
 *   4. Open the canvas text card in edit mode: the cell must read `![[renamed.png\|500]]` (backslash
 *      before the pipe preserved, table intact) — NOT `![[renamed.png|500]]` (which breaks the table).
 */

interface CanvasJson {
  nodes: CanvasTextNodeJson[];
}

interface CanvasTableSetupResult {
  readonly nodeTextOnDisk: string;
  readonly settingsFound: boolean;
}

interface CanvasTextNodeJson {
  text?: string;
}

/*
 * Desktop-only: no Android emulator is available in this environment. The canvas rewrite path is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to
 * Android once an emulator exists.
 */

describe('Canvas table sized embed survives the rewrite (issue #27)', () => {
  // A real check that the reproduction scenario is well-formed: the table-escaped sized embed is
  // Persisted into the canvas text node byte-for-byte (the input the rewrite must preserve).
  it('persists a table-escaped sized embed `\\|500` into a canvas text node', async () => {
    const result = await evalInObsidian({
      args: {},
      async fn({ app }): Promise<CanvasTableSetupResult> {
        const plugin = app.plugins.getPlugin('obsidian-custom-attachment-location');
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const imgName = `img-${stamp}.png`;
        await app.vault.createBinary(imgName, new ArrayBuffer(4));

        const nodeText = `| Header |\n| --- |\n| ![[${imgName}\\|500]] |`;
        const canvasData = {
          edges: [],
          nodes: [{ height: 400, id: 'text1', text: nodeText, type: 'text', width: 500, x: 0, y: 0 }]
        };
        const canvas = await app.vault.create(`board-${stamp}.canvas`, JSON.stringify(canvasData, null, 2));
        const content = await app.vault.read(canvas);
        const parsed = JSON.parse(content) as CanvasJson;
        const nodeTextOnDisk = parsed.nodes[0]?.text ?? '';
        return { nodeTextOnDisk, settingsFound: Boolean(plugin) };
      },
      vaultPath: getTempVault().path
    });

    expect(result.settingsFound).toBe(true);
    // The literal backslash-escaped divider survives the JSON round-trip (this is the exact input
    // The ODU `applyCanvasChanges` fix must preserve when it rewrites the embed).
    expect(result.nodeTextOnDisk).toMatch(/!\[\[[^[\]]*\.png\\\|500\]\]/);
  }, 120_000);

  /*
   * The behavioral rewrite assertion (skipped — see the G97 escape-hatch note above). Kept as
   * executable intent: were canvas text-node embeds discoverable headlessly, this would rename the
   * target through Collect and assert the rewritten embed keeps `\|500` (never an unescaped `|500`).
   */
  it.skip('keeps `\\|500` when the canvas text-node embed is rewritten (blocked: text-node embeds not discoverable headlessly)', () => {
    // Intentionally empty: the behavior is verified by the ODU unit test and the manual recipe above.
  });
});
