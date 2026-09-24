import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

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
      async callback({ app, findPluginSettingsComponent: findSettingsComponent }): Promise<ProbeResult> {
        interface MultipleNotesSettings {
          collectAttachmentUsedByMultipleNotesMode: string;
          excludePathsFromMultipleNotesCheck: string[];
          isExcludedFromMultipleNotesCheck: (path: string) => boolean;
        }

        function isMultipleNotesSettings(value: unknown): value is MultipleNotesSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isExcludedFromMultipleNotesCheck'] === 'function';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isMultipleNotesSettings);
        if (!settingsComponent) {
          return {
            control: { backlinkCount: -1, movedOut: false, newPaths: [] },
            fix: { backlinkCount: -1, movedOut: false, newPaths: [] },
            settingsFound: false
          };
        }

        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const component = settingsComponent;
        const priorMode = component.settings.collectAttachmentUsedByMultipleNotesMode;
        const priorExclude = [...component.settings.excludePathsFromMultipleNotesCheck];
        await component.editAndSave((settings) => {
          settings.collectAttachmentUsedByMultipleNotesMode = 'Skip';
        });
        const collectCommandId = 'obsidian-custom-attachment-location:collect-attachments-in-file';

        /*
         * Declares 11s of waiting and is called twice, so the closure declares 22s: under the transport's ~30s
         * per-closure default. The project raises its command timeout past that, but only as a backstop — a
         * closure that spends it dies as a bare transport timeout, never as the wait that overran.
         */
        async function runPhase(exclude: string[]): Promise<PhaseResult> {
          await component.editAndSave((settings) => {
            settings.excludePathsFromMultipleNotesCheck = exclude;
          });

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
          const resolveDeadline = Date.now() + 3000;
          while (Date.now() < resolveDeadline) {
            backlinkCount = imgFile ? app.metadataCache.getBacklinksForFile(imgFile).keys().length : 0;
            if (backlinkCount >= 2) {
              break;
            }
            await sleep(200);
          }

          await app.workspace.getLeaf(false).openFile(realNote);

          /*
           * The collect command reads the ACTIVE file, and `openFile` resolves before the workspace has
           * Finished switching to it. Firing the command too early collects nothing, which surfaces
           * Much later as `movedOut: false` — indistinguishable from the exclusion not working.
           */
          const activeDeadline = Date.now() + 3000;
          while (Date.now() < activeDeadline && app.workspace.getActiveFile()?.path !== realNote.path) {
            await sleep(100);
          }

          app.commands.executeCommandById(collectCommandId);

          // The collect runs on an internal queue; poll until the attachment leaves its original path.
          const collectDeadline = Date.now() + 5000;
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

        try {
          const control = await runPhase([]);
          const fix = await runPhase([String.raw`/\.excalidraw\.md$/`]);
          return { control, fix, settingsFound: true };
        } finally {
          await component.editAndSave((settings) => {
            settings.collectAttachmentUsedByMultipleNotesMode = priorMode;
            settings.excludePathsFromMultipleNotesCheck = priorExclude;
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
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
