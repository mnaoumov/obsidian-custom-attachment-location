import { evalInObsidian } from 'obsidian-integration-testing';
import { getTempVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #33: `excludePathsFromMultipleNotesCheck` must make the
 * "Collect attachments in current note" command ignore backlink notes whose path matches the
 * configured patterns when deciding whether an attachment is used by multiple notes.
 *
 * Scenario: an attachment referenced by one real note AND one `.excalidraw.md` note, with the
 * multiple-notes mode set to `Skip`:
 *   - control (no exclusion) -> two backlinks -> Skip -> the attachment is NOT collected;
 *   - fix (exclude `/\.excalidraw\.md$/`) -> the `.excalidraw` note is ignored -> one effective
 *     backlink -> the attachment IS collected (moved into the note's proper folder).
 */

interface PhaseResult {
  readonly backlinkCount: number;
  readonly movedOut: boolean;
  readonly newPaths: readonly string[];
}

interface ProbeResult {
  readonly control: PhaseResult;
  readonly fix: PhaseResult;
  readonly settingsFound: boolean;
}

describe('Collect attachments — exclude notes from the multiple-notes check (issue #33)', () => {
  it('ignores excluded backlink notes so a shared attachment is still collected', async () => {
    const result = await evalInObsidian({
      args: {},
      async fn({ app }): Promise<ProbeResult> {
        interface MultipleNotesSettings {
          collectAttachmentUsedByMultipleNotesMode: string;
          excludePathsFromMultipleNotesCheck: string[];
          isExcludedFromMultipleNotesCheck(path: string): boolean;
        }

        function isMultipleNotesSettings(value: unknown): value is MultipleNotesSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isExcludedFromMultipleNotesCheck'] === 'function';
        }

        // The plugin does not expose its settings publicly, so locate the live settings object
        // (the one the attachment collector reads) by walking the plugin's component tree.
        function findSettings(): MultipleNotesSettings | null {
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
            if (isMultipleNotesSettings(record['settings'])) {
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
          return {
            control: { backlinkCount: -1, movedOut: false, newPaths: [] },
            fix: { backlinkCount: -1, movedOut: false, newPaths: [] },
            settingsFound: false
          };
        }

        settings.collectAttachmentUsedByMultipleNotesMode = 'Skip';
        const collectCommandId = 'obsidian-custom-attachment-location:collect-attachments-in-file';

        async function runPhase(activeSettings: MultipleNotesSettings, exclude: string[]): Promise<PhaseResult> {
          activeSettings.excludePathsFromMultipleNotesCheck = exclude;

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const imgPath = `img-${stamp}.png`;
          const realNotePath = `real-note-${stamp}.md`;
          const excalidrawNotePath = `drawing-${stamp}.excalidraw.md`;

          await app.vault.createBinary(imgPath, new ArrayBuffer(4));
          const realNote = await app.vault.create(realNotePath, `![[${imgPath}]]`);
          await app.vault.create(excalidrawNotePath, `![[${imgPath}]]`);

          // Wait for the metadata cache to resolve both embeds so the collector sees two backlinks.
          const imgFile = app.vault.getFileByPath(imgPath);
          let backlinkCount = 0;
          const resolveDeadline = Date.now() + 8_000;
          while (Date.now() < resolveDeadline) {
            backlinkCount = imgFile ? app.metadataCache.getBacklinksForFile(imgFile).keys().length : 0;
            if (backlinkCount >= 2) {
              break;
            }
            await sleep(200);
          }

          await app.workspace.getLeaf(false).openFile(realNote);
          app.commands.executeCommandById(collectCommandId);

          // The collect runs on an internal queue; poll until the attachment leaves its original path.
          const collectDeadline = Date.now() + 12_000;
          while (Date.now() < collectDeadline) {
            if (!app.vault.getFileByPath(imgPath)) {
              break;
            }
            await sleep(200);
          }

          const base = imgPath.split('/').pop() ?? imgPath;
          const newPaths = app.vault.getFiles()
            .map((file) => file.path)
            .filter((path) => path !== imgPath && path.endsWith(base));
          return {
            backlinkCount,
            movedOut: !app.vault.getFileByPath(imgPath),
            newPaths
          };
        }

        const control = await runPhase(settings, []);
        const fix = await runPhase(settings, ['/\\.excalidraw\\.md$/']);
        return { control, fix, settingsFound: true };
      },
      vaultPath: getTempVault().path
    });

    expect(result.settingsFound).toBe(true);

    // Both phases really staged an attachment referenced by two notes.
    expect(result.control.backlinkCount).toBe(2);
    expect(result.fix.backlinkCount).toBe(2);

    // Control: without the exclusion the shared attachment is treated as multi-note and skipped.
    expect(result.control.movedOut).toBe(false);
    expect(result.control.newPaths).toStrictEqual([]);

    // Fix: excluding the `.excalidraw` note drops the effective count to one, so it is collected.
    expect(result.fix.movedOut).toBe(true);
    expect(result.fix.newPaths).toHaveLength(1);
    expect(result.fix.newPaths[0]).toMatch(/^assets\/real-note-.*\/img-.*\.png$/);
  }, 120_000);
});
