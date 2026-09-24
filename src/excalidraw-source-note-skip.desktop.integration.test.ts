import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * Desktop coverage for how the two per-note commands answer a file listed in `treatAsAttachmentExtensions`
 * (default `['.excalidraw.md']`), and why they answer it DIFFERENTLY.
 *
 *   - `Delete unused attachments in current note` is refused on such a file, and its sweep never scans one
 *     as a note. That sweep learns what a note references from the metadata cache, and a drawing keeps its
 *     references where the cache does not carry them (Excalidraw ships `compress: true` — see
 *     `externally-created-attachment-drawing-owner.desktop.integration.test.ts`), so scanning one returns an
 *     EMPTY reference set and every file in the folder it owns becomes a candidate to TRASH.
 *   - `Collect attachments in current note` is still OFFERED on it. Issues #57 and #75 both ship collecting
 *     FROM a drawing as their defining scenario (`note-priority.desktop.integration.test.ts`,
 *     `collect-higher-priority-notes.desktop.integration.test.ts`), so the collect-side skip that Consistent
 *     Attachments and Links, the plugin this collector is forked from, applies is deliberately not ported. This half guards
 *     against a later port quietly taking that entry point away again.
 *
 * Each question is asked through `checkCallback(true)` — the availability probe Obsidian itself uses before
 * listing a command, so nothing runs and nothing moves — and in TWO phases. The control phase makes the
 * drawing an ordinary note, where both commands are offered; the fix phase restores the default. Without the
 * control a refusal would pass whenever the command was missing altogether.
 *
 * `treatAsAttachmentExtensions` belongs to Advanced Rename and Delete Handler since 12.0.0 and this plugin
 * asks `isTreatedAsAttachment(path)` rather than reading the array, so what each phase swaps is a stub
 * parked on the read-back component's live `apiRef` — the technique the drawing-owner suite already uses,
 * and the reason the other plugin does not have to be reconfigured to run this.
 *
 * Desktop-only (the file name alone picks the project). The behavior itself is platform-agnostic.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COLLECT_IN_FILE_COMMAND_ID = `${PLUGIN_ID}:collect-attachments-in-file`;
const DELETE_UNUSED_IN_FILE_COMMAND_ID = `${PLUGIN_ID}:delete-unused-attachments-in-file`;

interface PhaseResult {
  readonly isCollectCommandOfferedOnDrawing: boolean;
  readonly isDeleteUnusedCommandOfferedOnDrawing: boolean;
}

interface ProbeResult {
  readonly control: PhaseResult;
  readonly fix: PhaseResult;
  readonly probesFound: boolean;
}

describe('A .excalidraw.md is never swept as a note, and is still collected from', () => {
  it('refuses Delete unused on a drawing only while its extension is treated as an attachment, and always offers Collect', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        collectInFileCommandId,
        deleteUnusedInFileCommandId,
        pluginId
      }): Promise<ProbeResult> {
        interface AvailabilityCheckableCommand {
          checkCallback?(isChecking: boolean): boolean | undefined;
        }

        interface HandedOverProvider {
          getSettings(): Record<string, unknown>;
          isPathIgnored(path: string): boolean;
          isTreatedAsAttachment(path: string): boolean;
        }

        interface HandedOverProviderRef {
          value: HandedOverProvider | null;
        }

        interface HandedOverSettingsHolder {
          apiRef: HandedOverProviderRef | null;
        }

        function isHandedOverSettingsHolder(value: unknown): value is HandedOverSettingsHolder {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && 'apiRef' in record
            && typeof record['isPathIgnored'] === 'function'
            && typeof record['isTreatedAsAttachment'] === 'function';
        }

        const pluginUnknown: unknown = app.plugins.getPlugin(pluginId);

        // The read-back component is not exposed publicly, so it is located by walking the plugin's
        // Component tree.
        function findInPluginTree<T>(match: (record: Record<string, unknown>) => null | T): null | T {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [pluginUnknown];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            const matched = match(record);
            if (matched !== null) {
              return matched;
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

        const EMPTY_PHASE: PhaseResult = {
          isCollectCommandOfferedOnDrawing: false,
          isDeleteUnusedCommandOfferedOnDrawing: false
        };

        const foundHolder = findInPluginTree((record) => isHandedOverSettingsHolder(record) ? record : null);
        const collectCommandUnknown: unknown = app.commands.commands[collectInFileCommandId];
        const deleteUnusedCommandUnknown: unknown = app.commands.commands[deleteUnusedInFileCommandId];
        const collectCommand = collectCommandUnknown as AvailabilityCheckableCommand | undefined;
        const deleteUnusedCommand = deleteUnusedCommandUnknown as AvailabilityCheckableCommand | undefined;
        if (!foundHolder || !collectCommand || !deleteUnusedCommand) {
          return { control: EMPTY_PHASE, fix: EMPTY_PHASE, probesFound: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const holder: HandedOverSettingsHolder = foundHolder;
        const collect: AvailabilityCheckableCommand = collectCommand;
        const deleteUnused: AvailabilityCheckableCommand = deleteUnusedCommand;
        const priorApiRef = holder.apiRef;

        async function runPhase(shouldTreatDrawingAsAttachment: boolean, label: string): Promise<PhaseResult> {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const drawingPath = `esn-${label}-drawing-${stamp}.excalidraw.md`;

          try {
            holder.apiRef = {
              value: {
                getSettings: (): Record<string, unknown> => ({
                  emptyFolderBehavior: 'DeleteWithEmptyParents',
                  notePriorities: [],
                  shouldRenameAttachmentFiles: false,
                  treatAsAttachmentExtensions: shouldTreatDrawingAsAttachment ? ['.excalidraw.md'] : []
                }),
                isPathIgnored: (): boolean => false,
                isTreatedAsAttachment: (path: string): boolean => shouldTreatDrawingAsAttachment && path.endsWith('.excalidraw.md')
              }
            };

            const drawing = await app.vault.create(drawingPath, '# drawing\n');
            await app.workspace.getLeaf(false).openFile(drawing);
            return {
              isCollectCommandOfferedOnDrawing: collect.checkCallback?.(true) === true,
              isDeleteUnusedCommandOfferedOnDrawing: deleteUnused.checkCallback?.(true) === true
            };
          } finally {
            // The desktop suite shares one vault, and sibling suites enumerate it and assert on exactly
            // Which files survive. Take the drawing back out.
            const existing = app.vault.getAbstractFileByPath(drawingPath);
            if (existing) {
              await app.fileManager.trashFile(existing);
            }
          }
        }

        try {
          const control = await runPhase(false, 'control');
          const fix = await runPhase(true, 'fix');
          return { control, fix, probesFound: true };
        } finally {
          // eslint-disable-next-line require-atomic-updates -- Restoring a value captured before the awaits; nothing else in this vault writes it.
          holder.apiRef = priorApiRef;
        }
      },
      input: {
        collectInFileCommandId: COLLECT_IN_FILE_COMMAND_ID,
        deleteUnusedInFileCommandId: DELETE_UNUSED_IN_FILE_COMMAND_ID,
        pluginId: PLUGIN_ID
      },
      vaultPath: getTemporaryVault().path
    });

    // Probes that could not be found would make every assertion below vacuous.
    expect(result.probesFound).toBe(true);

    // Without the extension treated as an attachment, the drawing is an ordinary note: both commands are
    // Offered on it.
    expect(result.control.isCollectCommandOfferedOnDrawing).toBe(true);
    expect(result.control.isDeleteUnusedCommandOfferedOnDrawing).toBe(true);

    // With it treated as an attachment, the sweep is refused rather than offered and then doing nothing —
    // While the collect stays offered, because #57 and #75 collect FROM a drawing.
    expect(result.fix.isCollectCommandOfferedOnDrawing).toBe(true);
    expect(result.fix.isDeleteUnusedCommandOfferedOnDrawing).toBe(false);
  }, 180_000);
});
