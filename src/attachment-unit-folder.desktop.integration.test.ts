import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #56 (G97): a folder listed in `attachmentUnitFolderPaths` is one
 * attachment. When "Collect attachments in current note" moves a link into such a folder, the whole
 * folder must travel, not just the linked file.
 *
 * The failure this prevents is silent: a saved `.html` page whose `_files/` siblings are left behind
 * still opens, it is simply blank. So the control phase is the point of the test — it proves the
 * hierarchy really is torn apart without the setting.
 */

interface PhaseResult {
  readonly diagnostics: string;
  readonly leftBehindPaths: readonly string[];
  readonly movedPaths: readonly string[];
  readonly noteFolder: string;
}

interface ProbeResult {
  readonly control: PhaseResult;
  readonly fix: PhaseResult;
  readonly settingsFound: boolean;
}

describe('Attachment unit folders travel whole (issue #56)', () => {
  it('moves the entire folder with the linked attachment, and only the file without the setting', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<ProbeResult> {
        interface UnitFolderSettings {
          attachmentUnitFolderPaths: string[];
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
          const queue: unknown[] = [app.plugins.getPlugin('obsidian-custom-attachment-location')];
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

        const EMPTY_PHASE: PhaseResult = { diagnostics: '', leftBehindPaths: [], movedPaths: [], noteFolder: '' };

        const foundSettings = findSettings();
        if (!foundSettings) {
          return { control: EMPTY_PHASE, fix: EMPTY_PHASE, settingsFound: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: UnitFolderSettings = foundSettings;

        const collectCommandId = 'obsidian-custom-attachment-location:collect-attachments-in-file';

        /*
         * Stages a saved-page-shaped attachment: a folder holding the linked image AND a sibling the
         * note never links to. That unlinked sibling is the whole point — it is what gets left behind
         * when only the linked file travels.
         */
        async function runPhase(shouldDesignateUnitFolder: boolean): Promise<PhaseResult> {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const unitFolderPath = `source-${stamp}/page_files`;
          const linkedPath = `${unitFolderPath}/logo.png`;
          const siblingPath = `${unitFolderPath}/sub/deep.css`;
          const noteName = `note-${stamp}`;

          await app.vault.createFolder(`${unitFolderPath}/sub`);
          await app.vault.createBinary(linkedPath, new ArrayBuffer(4));
          await app.vault.create(siblingPath, 'body {}');

          settings.attachmentUnitFolderPaths = shouldDesignateUnitFolder ? [unitFolderPath] : [];

          const note = await app.vault.create(`${noteName}.md`, `![[${linkedPath}]]`);

          // Wait for the metadata cache to resolve the embed, or the collector sees no links at all.
          let embedCount = 0;
          const resolveDeadline = Date.now() + 8000;
          while (Date.now() < resolveDeadline) {
            embedCount = app.metadataCache.getFileCache(note)?.embeds?.length ?? 0;
            if (embedCount > 0) {
              break;
            }
            await sleep(200);
          }

          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);
          app.commands.executeCommandById(collectCommandId);

          /*
           * The collect runs on an internal queue, so wait for the outcome itself rather than for the
           * linked file merely leaving its origin. That proxy is reached partway through a unit-folder
           * move, and the next phase then rewrites the settings while the first is still running.
           */
          const expectedPath = shouldDesignateUnitFolder ? `assets/${noteName}/page_files/logo.png` : `assets/${noteName}/logo.png`;
          const collectDeadline = Date.now() + 30_000;
          while (Date.now() < collectDeadline) {
            if (app.vault.getFileByPath(expectedPath)) {
              break;
            }
            await sleep(200);
          }
          // Let the queue settle so the next phase does not race this one's tail.
          await sleep(1000);

          const noteFolder = `assets/${noteName}`;
          const paths = app.vault.getFiles().map((file) => file.path);
          const related = paths.filter((path) => path.includes(stamp));
          const diagnostics = `embeds=${embedCount.toString()} noteContent=${JSON.stringify(await app.vault.read(note))} related=${JSON.stringify(related)}`;

          /*
           * The desktop suite shares one vault, and the collect / delete-unused tests enumerate it and
           * assert on exactly which files survive. Take everything this phase created back out.
           */
          leaf.detach();
          for (const path of related.reverse()) {
            const file = app.vault.getFileByPath(path);
            if (file) {
              await app.fileManager.trashFile(file);
            }
          }
          for (const folderPath of [`${noteFolder}/page_files/sub`, `${noteFolder}/page_files`, noteFolder, unitFolderPath, `source-${stamp}`]) {
            const folder = app.vault.getFolderByPath(folderPath);
            if (folder) {
              await app.fileManager.trashFile(folder);
            }
          }

          return {
            diagnostics,
            leftBehindPaths: paths.filter((path) => path.startsWith(`source-${stamp}/`)),
            movedPaths: paths.filter((path) => path.startsWith(`${noteFolder}/`)),
            noteFolder
          };
        }

        const previousUnitFolderPaths = settings.attachmentUnitFolderPaths;
        try {
          const control = await runPhase(false);
          const fix = await runPhase(true);
          return { control, fix, settingsFound: true };
        } finally {
          // eslint-disable-next-line require-atomic-updates -- Restoring a value captured before the awaits; nothing else in this vault writes it.
          settings.attachmentUnitFolderPaths = previousUnitFolderPaths;
        }
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // Control: only the linked file travels, and the sibling it needs is stranded.
    expect(result.control.movedPaths, result.control.diagnostics).toStrictEqual([`${result.control.noteFolder}/logo.png`]);
    expect(result.control.leftBehindPaths).toHaveLength(1);
    expect(result.control.leftBehindPaths[0]).toMatch(/\/page_files\/sub\/deep\.css$/);

    // Fix: the whole folder travels, keeping its internal shape, and nothing is stranded.
    expect([...result.fix.movedPaths].sort()).toStrictEqual([
      `${result.fix.noteFolder}/page_files/logo.png`,
      `${result.fix.noteFolder}/page_files/sub/deep.css`
    ]);
    expect(result.fix.leftBehindPaths).toStrictEqual([]);
  }, 180_000);
});
