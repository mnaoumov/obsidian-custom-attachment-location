import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #46: the opt-in `shouldSkipCollectingAttachmentsReferencedByRawPath`
 * safety net. An attachment is embedded with a normal `![[...]]` wikilink in the active note AND
 * referenced by a RAW `<img src="...">` in another note (a reference Obsidian does NOT index, the
 * kind other plugins produce). Collecting the active note:
 *   - control (setting off) -> the attachment IS moved into the note's proper folder, breaking the
 *     raw reference (this is the data-loss scenario the issue reports);
 *   - fix (setting on) -> the raw reference is detected, so the attachment is left in place.
 */

interface PhaseResult {
  readonly backlinkCount: number;
  readonly movedOut: boolean;
}

interface ProbeResult {
  readonly control: PhaseResult;
  readonly fix: PhaseResult;
  readonly settingsFound: boolean;
}

describe('Collect attachments — raw path safety net (issue #46)', () => {
  it('leaves an attachment referenced by a non-indexed raw path in place when the setting is on', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<ProbeResult> {
        interface RawPathSettings {
          collectAttachmentUsedByMultipleNotesMode: string;
          isExcludedFromMultipleNotesCheck(path: string): boolean;
          shouldSkipCollectingAttachmentsReferencedByRawPath: boolean;
        }

        function isRawPathSettings(value: unknown): value is RawPathSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isExcludedFromMultipleNotesCheck'] === 'function'
            && 'shouldSkipCollectingAttachmentsReferencedByRawPath' in (value as Record<string, unknown>);
        }

        // The plugin does not expose its settings publicly, so locate the live settings object
        // (the one the attachment collector reads) by walking the plugin's component tree.
        function findSettings(): null | RawPathSettings {
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
            if (isRawPathSettings(record['settings'])) {
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
          return {
            control: { backlinkCount: -1, movedOut: false },
            fix: { backlinkCount: -1, movedOut: false },
            settingsFound: false
          };
        }

        settings.collectAttachmentUsedByMultipleNotesMode = 'Move';
        const collectCommandId = 'obsidian-custom-attachment-location:collect-attachments-in-file';

        async function runPhase(activeSettings: RawPathSettings, shouldSkip: boolean): Promise<PhaseResult> {
          activeSettings.shouldSkipCollectingAttachmentsReferencedByRawPath = shouldSkip;

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const imgPath = `img-${stamp}.png`;
          const activeNotePath = `active-${stamp}.md`;
          const rawNotePath = `raw-${stamp}.md`;

          await app.vault.createBinary(imgPath, new ArrayBuffer(4));
          const activeNote = await app.vault.create(activeNotePath, `![[${imgPath}]]`);
          // Raw HTML embed: Obsidian does not index this reference, so it is invisible to collecting.
          await app.vault.create(rawNotePath, `<img src="${imgPath}">`);

          // Wait for the metadata cache to resolve the indexed embed so the collector sees one backlink.
          const imgFile = app.vault.getFileByPath(imgPath);
          let backlinkCount = 0;
          const resolveDeadline = Date.now() + 8000;
          while (Date.now() < resolveDeadline) {
            backlinkCount = imgFile ? app.metadataCache.getBacklinksForFile(imgFile).keys().length : 0;
            if (backlinkCount >= 1) {
              break;
            }
            await sleep(200);
          }

          await app.workspace.getLeaf(false).openFile(activeNote);
          app.commands.executeCommandById(collectCommandId);

          // The collect runs on an internal queue; poll until the attachment leaves its original path.
          const collectDeadline = Date.now() + 12_000;
          while (Date.now() < collectDeadline) {
            if (!app.vault.getFileByPath(imgPath)) {
              break;
            }
            await sleep(200);
          }

          return {
            backlinkCount,
            movedOut: !app.vault.getFileByPath(imgPath)
          };
        }

        const control = await runPhase(settings, false);
        const fix = await runPhase(settings, true);
        return { control, fix, settingsFound: true };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // Both phases really staged an attachment with one indexed backlink plus a raw reference.
    expect(result.control.backlinkCount).toBe(1);
    expect(result.fix.backlinkCount).toBe(1);

    // Control: without the safety net the attachment is relocated even though a raw reference exists.
    expect(result.control.movedOut).toBe(true);

    // Fix: the raw reference is detected, so the attachment is left in place.
    expect(result.fix.movedOut).toBe(false);
  }, 120_000);
});
