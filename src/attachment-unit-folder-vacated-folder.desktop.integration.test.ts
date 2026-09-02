import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #69 (G97): an attachment unit folder travels whole, so the folder it
 * was carried OUT of is the one left empty — and, with a deleting `emptyFolderBehavior`, the one that
 * must be swept.
 *
 * The bug was invisible from the moved side: the collect recorded the linked file's own parent as the
 * vacated folder, but that parent rides along inside the tree. Sweeping it hit a path that no longer
 * existed and silently did nothing, while the real parent — holding nothing but the unit folder that
 * just left — survived. So the staged source folder holds the unit folder and NOTHING else: it is
 * exactly the "last item moved out" the reporter described.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COLLECT_COMMAND_ID = 'obsidian-custom-attachment-location:collect-attachments-in-file';
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface ProbeResult {
  readonly diagnostics: string;
  readonly movedPaths: readonly string[];
  readonly noteFolder: string;
  readonly settingsFound: boolean;
  readonly wasVacatedFolderDeleted: boolean;
}

describe('Collect deletes the folder an attachment unit folder was carried out of (issue #69)', () => {
  it('deletes the vacated parent when the unit folder was its last item', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        collectCommandId,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface UnitFolderSettings {
          attachmentFolderPath: string;
          attachmentUnitFolderPaths: string[];
          emptyFolderBehavior: string;
          isAttachmentUnitFolder(path: string): boolean;
        }

        function isUnitFolderSettings(value: unknown): value is UnitFolderSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function';
        }

        // The plugin does not expose its settings publicly, so locate the live settings object
        // (the one the attachment collector reads) by walking the plugin's component tree.
        function findSettings(): null | UnitFolderSettings {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [app.plugins.getPlugin(pluginId)];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            if (isUnitFolderSettings(record['settings'])) {
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

        const foundSettings = findSettings();
        if (!foundSettings) {
          return { diagnostics: '', movedPaths: [], noteFolder: '', settingsFound: false, wasVacatedFolderDeleted: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: UnitFolderSettings = foundSettings;

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone: the collect pass
         * moves and removes entries on its own queue, and trashing one a second time throws `ENOENT`
         * from the rename into `.trash`.
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

        const priorFolderPath = settings.attachmentFolderPath;
        const priorUnitFolderPaths = settings.attachmentUnitFolderPaths;
        const priorEmptyFolderBehavior = settings.emptyFolderBehavior;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const sourceFolderPath = `uf-source-${stamp}`;
        const unitFolderPath = `${sourceFolderPath}/page_files`;
        const linkedPath = `${unitFolderPath}/logo.png`;
        const siblingPath = `${unitFolderPath}/sub/deep.css`;
        const noteBaseName = `uf-note-${stamp}`;
        const notePath = `${noteBaseName}.md`;
        const noteFolder = `assets/${noteBaseName}`;
        const movedLinkedPath = `${noteFolder}/page_files/logo.png`;

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './assets/${noteFileName}';
          settings.attachmentUnitFolderPaths = [unitFolderPath];
          settings.emptyFolderBehavior = 'DeleteWithEmptyParents';

          await app.vault.createFolder(`${unitFolderPath}/sub`);
          await app.vault.createBinary(linkedPath, new ArrayBuffer(4));
          // The unlinked sibling is what makes the folder a unit rather than a single file.
          await app.vault.create(siblingPath, 'body {}');
          const note = await app.vault.create(notePath, `![[${linkedPath}]]\n`);

          await waitUntil({
            message: 'the embed was never indexed, so the collector would have seen no links at all',
            predicate: () => (app.metadataCache.getFileCache(note)?.embeds?.length ?? 0) > 0,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);

          /*
           * The collect command reads the ACTIVE file, and `openFile` resolves before the workspace has
           * Finished switching to it. Firing the command too early collects nothing at all.
           */
          await waitUntil({
            message: 'the staged note never became the active file',
            predicate: () => app.workspace.getActiveFile()?.path === note.path,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          app.commands.executeCommandById(collectCommandId);

          await waitUntil({
            message: 'the unit folder never arrived in the note attachment folder',
            predicate: () => app.vault.getFileByPath(movedLinkedPath) !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          /*
           * The sweep runs after the whole note's links are processed, so the arrival above does not
           * Imply it has happened yet. Wait for the folder to go, and report the wait timing out as
           * The defect itself rather than as a harness error, so the assertion below can say why.
           */
          let wasVacatedFolderDeleted: boolean;
          try {
            await waitUntil({
              message: `${sourceFolderPath} outlived the unit folder that was its last item`,
              predicate: () => app.vault.getFolderByPath(sourceFolderPath) === null,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
            wasVacatedFolderDeleted = true;
          } catch {
            wasVacatedFolderDeleted = app.vault.getFolderByPath(sourceFolderPath) === null;
          }

          const paths = app.vault.getFiles().map((file) => file.path);
          const related = paths.filter((path) => path.includes(stamp));
          leaf.detach();

          return {
            diagnostics: `related=${JSON.stringify(related)}`,
            movedPaths: related.filter((path) => path.startsWith(`${noteFolder}/`)).sort(),
            noteFolder,
            settingsFound: true,
            wasVacatedFolderDeleted
          };
        } finally {
          /*
           * The desktop suite shares one vault, and the collect / delete-unused tests enumerate it and
           * Assert on exactly which files survive. Take everything this test created back out.
           */
          await trashIfExists(notePath);
          for (
            const path of [
              `${noteFolder}/page_files/sub`,
              `${noteFolder}/page_files`,
              noteFolder,
              `${unitFolderPath}/sub`,
              unitFolderPath,
              sourceFolderPath
            ]
          ) {
            await trashIfExists(path);
          }
          // Restoring values captured before the awaits; nothing else in this vault writes them.
          settings.attachmentFolderPath = priorFolderPath;
          settings.attachmentUnitFolderPaths = priorUnitFolderPaths;
          settings.emptyFolderBehavior = priorEmptyFolderBehavior;
        }
      },
      input: {
        collectCommandId: COLLECT_COMMAND_ID,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // The whole tree moved, which is the precondition the vacated-folder claim rests on.
    expect(result.movedPaths, result.diagnostics).toStrictEqual([
      `${result.noteFolder}/page_files/logo.png`,
      `${result.noteFolder}/page_files/sub/deep.css`
    ]);

    // The point of the issue: the folder the unit folder left behind is gone, not merely empty.
    expect(result.wasVacatedFolderDeleted, result.diagnostics).toBe(true);
  }, 180_000);
});
