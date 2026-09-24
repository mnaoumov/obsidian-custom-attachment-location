import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * Desktop coverage for the direction of `treatAsAttachmentExtensions` (default `['.excalidraw.md']`) that
 * says a file listed there is never scanned as a SOURCE note, so whatever is written inside it is left
 * exactly as it is.
 *
 * That is issue #151's actual guarantee. Excalidraw stores each drawing's embedded-image references
 * inside the `.excalidraw.md` itself, and rewriting them stops the drawing rendering. Collecting an
 * attachment is a move plus a rewrite of the referencing file, so a drawing whose own attachments moved
 * would necessarily have been rewritten — there was never a middle option to design. The guarantee
 * therefore lives entirely in the collector's walk
 * (`attachment-collector.ts:collectAttachmentsInAbstractFilesImpl`), which selects notes with the
 * plugin's `isNoteEx` rather than obsidian-dev-utils' plain extension-based `isNote`. Before that it used
 * `isNote`, and a drawing WAS scanned, moved and rewritten; the same defect was measured against a real
 * Obsidian in the plugin this collector is forked from.
 *
 * The suite drives the folder-wide collect over a folder holding a drawing and an ordinary sibling note,
 * and runs it TWICE. The control phase makes the drawing an ordinary note, so its image DOES travel and
 * its contents ARE rewritten; the fix phase restores the default and only the sibling's image travels.
 * Without the control phase this would pass whenever the collect silently did nothing.
 *
 * The sibling's image is asserted in BOTH phases, so a run where the collect never happened fails loudly
 * rather than reading as "the drawing was correctly skipped". The drawing sorts before the sibling inside
 * the scanned folder (the walk sorts by path, and the names start `a-` and `b-`), so the sibling's image
 * arriving means the drawing has already been through the loop — there is no race to wait out.
 *
 * Each phase also probes BOTH file commands with the drawing active, via `checkCallback(true)` — the same
 * availability question Obsidian asks before listing a command, so the probe moves nothing:
 *
 *   - `Collect attachments in current note`, whose walk skips the drawing, so offering it would offer a
 *     command that silently does nothing;
 *   - `Delete unused attachments in current note`, which is refused for a reason of its own rather than
 *     #151's. That sweep learns what a note references from the metadata cache, and a drawing keeps its
 *     references where the cache does not carry them (Excalidraw ships `compress: true` — see
 *     `externally-created-attachment-drawing-owner.desktop.integration.test.ts`), so scanning one returns
 *     an EMPTY reference set and every file in the folder it owns becomes a candidate to TRASH.
 *
 * `treatAsAttachmentExtensions` belongs to Advanced Rename and Delete Handler since 12.0.0 and this plugin
 * asks `isTreatedAsAttachment(path)` rather than reading the array, so what each phase swaps is a stub
 * parked on the read-back component's live `apiRef` — the technique the drawing-owner suite already uses,
 * and the reason the other plugin does not have to be reconfigured to run this.
 *
 * Collecting anything other than a single file confirms first, and nothing else in the harness answers
 * that modal — leave it and the operation parks in the plugin's queue, swallowing every LATER suite's
 * collect too. So the suite clicks the OK of the container that APPEARED, not the first `.mod-cta` in the
 * document: the shared desktop vault can already be showing a modal of its own, and dismissing that one
 * instead is indistinguishable from the collect having silently done nothing.
 *
 * The opposite direction — a drawing REFERENCED by a note travels as that note's attachment — is covered
 * by the plugin's own excalidraw attachment-collecting coverage.
 *
 * Desktop-only (the file name alone picks the project). The behavior itself is platform-agnostic.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COLLECT_IN_FILE_COMMAND_ID = `${PLUGIN_ID}:collect-attachments-in-file`;
const DELETE_UNUSED_IN_FILE_COMMAND_ID = `${PLUGIN_ID}:delete-unused-attachments-in-file`;
/*
 * Under the transport's ~30s per-closure cap, not at it. The closure spends this ceiling three times per
 * phase and runs two phases, so a larger value declares more than the cap allows and the eval is killed
 * and reported as a bare transport timeout — naming the harness rather than the wait that overran. Every
 * step it guards is a vault write or a queued collect in a small temporary vault.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 4000;

interface PhaseResult {
  readonly isCollectCommandOfferedOnDrawing: boolean;
  readonly isDeleteUnusedCommandOfferedOnDrawing: boolean;
  readonly isDrawingContentUnchanged: boolean;
  readonly isDrawingImageCollected: boolean;
  readonly isSiblingImageCollected: boolean;
}

interface ProbeResult {
  readonly control: PhaseResult;
  readonly fix: PhaseResult;
  readonly probesFound: boolean;
}

describe('A .excalidraw.md is never scanned as a source note (issue #151)', () => {
  it('leaves a drawing and its own attachment alone only while its extension is treated as an attachment', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        collectInFileCommandId,
        deleteUnusedInFileCommandId,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface AvailabilityCheckableCommand {
          checkCallback?(isChecking: boolean): boolean | undefined;
        }

        type CollectAttachmentsInAbstractFilesFunction = (abstractFiles: unknown[]) => void;

        interface CollectDestinationSettings {
          attachmentFolderPath: string;
          collectedAttachmentFolderPath: string;
          shouldRenameCollectedAttachments: boolean;
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

        function isCollectDestinationSettings(value: unknown): value is CollectDestinationSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['collectedAttachmentFolderPath'] === 'string'
            && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
        }

        function isHandedOverSettingsHolder(value: unknown): value is HandedOverSettingsHolder {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && 'apiRef' in record
            && typeof record['isPathIgnored'] === 'function'
            && typeof record['isTreatedAsAttachment'] === 'function';
        }

        const pluginUnknown: unknown = app.plugins.getPlugin(pluginId);
        const pluginRecord = pluginUnknown as null | Record<string, unknown>;

        // Neither the settings nor the read-back component is exposed publicly, so both are located by
        // Walking the plugin's component tree.
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
          isDeleteUnusedCommandOfferedOnDrawing: false,
          isDrawingContentUnchanged: false,
          isDrawingImageCollected: false,
          isSiblingImageCollected: false
        };

        const foundSettings = findInPluginTree((record) => isCollectDestinationSettings(record['settings']) ? record['settings'] : null);
        const foundHolder = findInPluginTree((record) => isHandedOverSettingsHolder(record) ? record : null);
        const foundCollect = pluginRecord?.['collectAttachmentsInAbstractFiles'];
        if (!foundSettings || !foundHolder || typeof foundCollect !== 'function') {
          return { control: EMPTY_PHASE, fix: EMPTY_PHASE, probesFound: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: CollectDestinationSettings = foundSettings;
        const holder: HandedOverSettingsHolder = foundHolder;
        const collectAttachmentsInAbstractFiles = foundCollect as CollectAttachmentsInAbstractFilesFunction;

        const priorCollectedFolderPath = settings.collectedAttachmentFolderPath;
        const wasRenamingCollectedAttachments = settings.shouldRenameCollectedAttachments;
        const priorApiRef = holder.apiRef;

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone: the collect pass moves
         * and removes entries on its own queue, and trashing one a second time throws `ENOENT` from the
         * rename into `.trash`.
         */
        async function trashIfExists(path: string): Promise<void> {
          const existing = app.vault.getAbstractFileByPath(path);
          if (!existing) {
            return;
          }
          try {
            await app.fileManager.trashFile(existing);
          } catch {
            // Removed between the lookup and the trash, which is the outcome this wanted anyway.
          }
        }

        /*
         * Stages a scanned folder holding a drawing and an ordinary sibling note, each embedding its own
         * image from a folder OUTSIDE the scanned one, so a collect has somewhere to move them from.
         */
        async function runPhase(shouldTreatDrawingAsAttachment: boolean, label: string): Promise<PhaseResult> {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const properFolder = `esn-proper-${label}-${stamp}`;
          const scanFolder = `esn-scan-${label}-${stamp}`;
          const outsideFolder = `esn-out-${label}-${stamp}`;
          const drawingImagePath = `${outsideFolder}/esn-drawing-image-${stamp}.png`;
          const siblingImagePath = `${outsideFolder}/esn-sibling-image-${stamp}.png`;
          // `a-` before `b-`: the walk sorts its notes by path, so the sibling's image arriving means the
          // Drawing has already been through the loop and there is no race left to wait out.
          const drawingPath = `${scanFolder}/a-drawing-${stamp}.excalidraw.md`;
          const siblingPath = `${scanFolder}/b-sibling-${stamp}.md`;
          const drawingContent = `# drawing\n\n![[${drawingImagePath}]]\n`;

          try {
            settings.collectedAttachmentFolderPath = properFolder;
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

            await app.vault.createFolder(scanFolder);
            await app.vault.createFolder(outsideFolder);
            await app.vault.createBinary(drawingImagePath, new ArrayBuffer(4));
            await app.vault.createBinary(siblingImagePath, new ArrayBuffer(4));
            const drawing = await app.vault.create(drawingPath, drawingContent);
            const sibling = await app.vault.create(siblingPath, `![[${siblingImagePath}]]\n`);

            // The embeds must be indexed, or the collector walks notes with no links and moves nothing —
            // Which in the fix phase is indistinguishable from the drawing being correctly skipped.
            await waitUntil({
              message: 'the staged embeds were not indexed',
              predicate: () =>
                (app.metadataCache.getFileCache(drawing)?.embeds?.length ?? 0) > 0
                && (app.metadataCache.getFileCache(sibling)?.embeds?.length ?? 0) > 0,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            // The command half. `checkCallback(true)` is the availability probe Obsidian itself uses to
            // Decide whether to list a command, so this asks the question without running anything —
            // Leaving the folder collect below as the only thing that moves a file.
            await app.workspace.getLeaf(false).openFile(drawing);
            const collectCommandUnknown: unknown = app.commands.commands[collectInFileCommandId];
            const deleteUnusedCommandUnknown: unknown = app.commands.commands[deleteUnusedInFileCommandId];
            const collectCommand = collectCommandUnknown as AvailabilityCheckableCommand | undefined;
            const deleteUnusedCommand = deleteUnusedCommandUnknown as AvailabilityCheckableCommand | undefined;
            const isCollectCommandOfferedOnDrawing = collectCommand?.checkCallback?.(true) === true;
            const isDeleteUnusedCommandOfferedOnDrawing = deleteUnusedCommand?.checkCallback?.(true) === true;

            // The walk half: collecting the folder reaches the drawing and the sibling alike, through the
            // `Vault.recurseChildren` arm rather than the direct-file one.
            const scanFolderFile = app.vault.getAbstractFileByPath(scanFolder);
            const modalCountBefore = document.querySelectorAll('.modal-container').length;
            collectAttachmentsInAbstractFiles.call(pluginRecord, [scanFolderFile]);

            await waitUntil({
              message: 'the collect confirmation modal never appeared',
              predicate: () => document.querySelectorAll('.modal-container').length > modalCountBefore,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
            const confirmButton = [...document.querySelectorAll('.modal-container')].at(-1)?.querySelector('button.mod-cta');
            if (confirmButton instanceof HTMLElement) {
              confirmButton.click();
            }

            // The sibling's image travels in BOTH phases, so it is the signal that the collect ran at all.
            await waitUntil({
              message: 'the sibling note\'s image was not collected, so the flow never ran',
              predicate: () => app.vault.getFileByPath(siblingImagePath) === null,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            const collectedPaths = app.vault.getFiles().map((file) => file.path).filter((path) => path.startsWith(`${properFolder}/`));
            return {
              isCollectCommandOfferedOnDrawing,
              isDeleteUnusedCommandOfferedOnDrawing,
              isDrawingContentUnchanged: (await app.vault.read(drawing)) === drawingContent,
              isDrawingImageCollected: collectedPaths.some((path) => path.includes('-drawing-image-')),
              isSiblingImageCollected: collectedPaths.some((path) => path.includes('-sibling-image-'))
            };
          } finally {
            // The desktop suite shares one vault, and sibling suites enumerate it and assert on exactly
            // Which files survive. Take everything this phase created back out.
            const createdPaths = app.vault.getFiles().map((file) => file.path).filter((filePath) => filePath.includes(stamp)).reverse();
            for (const createdPath of createdPaths) {
              await trashIfExists(createdPath);
            }
            await trashIfExists(scanFolder);
            await trashIfExists(outsideFolder);
            await trashIfExists(properFolder);
          }
        }

        try {
          // The collected file has to keep its own name, or it could not be told from the other phase's.
          settings.shouldRenameCollectedAttachments = false;
          const control = await runPhase(false, 'control');
          const fix = await runPhase(true, 'fix');
          return { control, fix, probesFound: true };
        } finally {
          /* eslint-disable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
          settings.collectedAttachmentFolderPath = priorCollectedFolderPath;
          settings.shouldRenameCollectedAttachments = wasRenamingCollectedAttachments;
          holder.apiRef = priorApiRef;
          /* eslint-enable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
        }
      },
      input: {
        collectInFileCommandId: COLLECT_IN_FILE_COMMAND_ID,
        deleteUnusedInFileCommandId: DELETE_UNUSED_IN_FILE_COMMAND_ID,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    // Probes that could not be found would make every assertion below vacuous.
    expect(result.probesFound).toBe(true);

    // Both phases really collected, so the difference between them is the predicate and nothing else.
    expect(result.control.isSiblingImageCollected).toBe(true);
    expect(result.fix.isSiblingImageCollected).toBe(true);

    // Without the extension treated as an attachment, the drawing is an ordinary note: both commands are
    // Offered on it, its own attachment is collected, and the reference written inside it is rewritten.
    expect(result.control.isCollectCommandOfferedOnDrawing).toBe(true);
    expect(result.control.isDeleteUnusedCommandOfferedOnDrawing).toBe(true);
    expect(result.control.isDrawingImageCollected).toBe(true);
    expect(result.control.isDrawingContentUnchanged).toBe(false);

    // With it treated as an attachment, the drawing is an attachment: both commands are refused rather
    // Than offered and then doing nothing, its attachment stays where it is, and its bytes are untouched.
    expect(result.fix.isCollectCommandOfferedOnDrawing).toBe(false);
    expect(result.fix.isDeleteUnusedCommandOfferedOnDrawing).toBe(false);
    expect(result.fix.isDrawingImageCollected).toBe(false);
    expect(result.fix.isDrawingContentUnchanged).toBe(true);
  }, 180_000);
});
