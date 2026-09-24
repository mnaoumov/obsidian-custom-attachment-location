import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #80: `excludeExtensionsFromMultipleNotesCheck` must make the
 * "Collect attachments in current note" command skip the multiple-notes check entirely for attachments
 * whose file type the user has declared deliberately shared.
 *
 * It is the twin of `collect-attachments-exclusion.desktop.integration.test.ts`, which proves the other
 * axis (issue #33, the NOTE paths that do not count as a second referrer). The two are separate files
 * because the thing being staged differs: there a second referring note, here a second referring note
 * that is perfectly ordinary and must stay counted for every attachment but the listed one.
 *
 * Scenario: an attachment referenced by TWO ordinary notes, with the multiple-notes mode set to `Skip`:
 *   - control (empty list) -> two backlinks -> Skip -> the attachment is NOT collected;
 *   - fix (list the attachment's extension) -> the check never runs -> the attachment IS collected.
 *
 * The control phase is the load-bearing half. Without it the fix phase would pass just as well against a
 * build that had stopped running the multiple-notes check at all.
 */

interface PhaseResult {
  readonly backlinkCount: number;
  readonly movedOut: boolean;
  readonly newPaths: readonly string[];
}

interface ProbeResult {
  readonly control: PhaseResult;
  readonly fix: PhaseResult;
  readonly otherTypeStillAsks: PhaseResult;
  readonly settingsFound: boolean;
}

describe('Collect attachments — exclude attachment extensions from the multiple-notes check (issue #80)', () => {
  it('collects a listed file type although several notes reference it', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<ProbeResult> {
        interface MultipleNotesSettings {
          collectAttachmentUsedByMultipleNotesMode: string;
          excludeExtensionsFromMultipleNotesCheck: string[];
          isExtensionExcludedFromMultipleNotesCheck: (path: string) => boolean;
        }

        function isMultipleNotesSettings(value: unknown): value is MultipleNotesSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isExtensionExcludedFromMultipleNotesCheck'] === 'function';
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

        const emptyPhase: PhaseResult = { backlinkCount: -1, movedOut: false, newPaths: [] };

        const settings = findSettings();
        if (!settings) {
          return {
            control: emptyPhase,
            fix: emptyPhase,
            otherTypeStillAsks: emptyPhase,
            settingsFound: false
          };
        }

        settings.collectAttachmentUsedByMultipleNotesMode = 'Skip';
        const collectCommandId = 'obsidian-custom-attachment-location:collect-attachments-in-file';

        /*
         * Declares 8s of waiting and is called THREE times, so the closure declares 24s: under the transport's
         * ~30s per-closure default. The project raises its command timeout past that, but only as a backstop — a
         * closure that spends it dies as a bare transport timeout, never as the wait that overran. Two of the
         * three phases expect the attachment to STAY, so their collect wait runs out on the passing path; the
         * collect itself finishes well inside it in this small vault.
         */
        async function runPhase(activeSettings: MultipleNotesSettings, excludeExtensions: string[], attachmentExtension: string): Promise<PhaseResult> {
          activeSettings.excludeExtensionsFromMultipleNotesCheck = excludeExtensions;

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const attachmentPath = `shared-${stamp}.${attachmentExtension}`;
          const firstNotePath = `first-note-${stamp}.md`;
          const secondNotePath = `second-note-${stamp}.md`;

          await app.vault.createBinary(attachmentPath, new ArrayBuffer(4));
          const firstNote = await app.vault.create(firstNotePath, `![[${attachmentPath}]]`);
          await app.vault.create(secondNotePath, `![[${attachmentPath}]]`);

          // Wait for the metadata cache to resolve both embeds so the collector sees two backlinks.
          const attachmentFile = app.vault.getFileByPath(attachmentPath);
          let backlinkCount = 0;
          const resolveDeadline = Date.now() + 2000;
          while (Date.now() < resolveDeadline) {
            backlinkCount = attachmentFile ? app.metadataCache.getBacklinksForFile(attachmentFile).keys().length : 0;
            if (backlinkCount >= 2) {
              break;
            }
            await sleep(200);
          }

          await app.workspace.getLeaf(false).openFile(firstNote);

          /*
           * The collect command reads the ACTIVE file, and `openFile` resolves before the workspace has
           * Finished switching to it. Firing the command too early collects nothing, which surfaces
           * Much later as `movedOut: false` — indistinguishable from the exemption not working.
           */
          const activeDeadline = Date.now() + 2000;
          while (Date.now() < activeDeadline && app.workspace.getActiveFile()?.path !== firstNote.path) {
            await sleep(100);
          }

          app.commands.executeCommandById(collectCommandId);

          // The collect runs on an internal queue; poll until the attachment leaves its original path.
          const collectDeadline = Date.now() + 4000;
          while (Date.now() < collectDeadline) {
            if (!app.vault.getFileByPath(attachmentPath)) {
              break;
            }
            await sleep(200);
          }

          const base = attachmentPath.split('/').pop() ?? attachmentPath;
          const newPaths = app.vault.getFiles()
            .map((file) => file.path)
            .filter((path) => path !== attachmentPath && path.endsWith(base));
          return {
            backlinkCount,
            movedOut: !app.vault.getFileByPath(attachmentPath),
            newPaths
          };
        }

        const control = await runPhase(settings, [], 'af');
        const fix = await runPhase(settings, ['.AF'], 'af');
        const otherTypeStillAsks = await runPhase(settings, ['.AF'], 'png');
        return {
          control,
          fix,
          otherTypeStillAsks,
          settingsFound: true
        };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // Every phase really staged an attachment referenced by two ordinary notes.
    expect(result.control.backlinkCount).toBe(2);
    expect(result.fix.backlinkCount).toBe(2);
    expect(result.otherTypeStillAsks.backlinkCount).toBe(2);

    // Control: with an empty list the shared attachment is treated as multi-note and skipped.
    expect(result.control.movedOut).toBe(false);
    expect(result.control.newPaths).toStrictEqual([]);

    // Fix: listing the extension skips the check, so it is collected. `.AF` against a `.af` file also
    // Proves the matching is case-insensitive and tolerates the leading dot, in the real settings object.
    expect(result.fix.movedOut).toBe(true);
    expect(result.fix.newPaths).toHaveLength(1);
    expect(result.fix.newPaths[0]).toMatch(/^assets\/first-note-.*\/shared-.*\.af$/);

    // The list is not a blanket switch: with the SAME setting in place, a file type not on it still asks.
    expect(result.otherTypeStillAsks.movedOut).toBe(false);
    expect(result.otherTypeStillAsks.newPaths).toStrictEqual([]);
  }, 180_000);
});
