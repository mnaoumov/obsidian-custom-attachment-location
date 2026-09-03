import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for T847 (G97): the vault-wide sweep reaching an attachment folder whose owning note
 * no longer exists.
 *
 * The scenario is the one no note-driven scan can reach. An attachment folder is visited only through the
 * note that resolves to it, so when that note is gone -- deleted by a sync client, which fires no event this
 * plugin can see -- nothing in the vault points at the folder and the sweep walks straight past it.
 *
 * Both halves run in ONE Obsidian session, because the first half is the regression guard for the second:
 * with the mode off the file must SURVIVE the sweep, and only after the mode is turned on must the very same
 * file be found. A test that only asserted the second half would pass just as well against a sweep that
 * deleted everything it saw.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const DELETE_COMMAND_ID = 'obsidian-custom-attachment-location:delete-unused-attachments-entire-vault';
const ORPHAN_SCAN_MODE_NONE = 'None';
const ORPHAN_SCAN_MODE_LISTED_PATHS = 'Listed paths';

/*
 * TWO full sweeps plus their settling run inside a single `evalInObsidian` callback, so their sum has to fit
 * the test's own 180s budget with room to spare. Sized generously: the trash step runs on the plugin's
 * internal queue behind whatever else is in flight, and cutting it too fine just converts a slow-but-correct
 * pass into "the orphan was never trashed".
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface ProbeResult {
  readonly confirmText: string;
  readonly isKeptAliveAfterScan: boolean;
  readonly isOrphanGoneAfterScan: boolean;
  readonly isOrphanKeptWhileModeOff: boolean;
  readonly modeOffNoticeText: string;
  readonly settingsFound: boolean;
}

describe('Delete unused attachments in entire vault, for attachments no note owns (T847)', () => {
  it('walks past an ownerless attachment folder until the mode is on, then trashes it', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        deleteCommandId,
        lib: { waitUntil },
        listedPathsMode,
        noneMode,
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        const SETTLE_DELAY_IN_MILLISECONDS = 1000;

        interface RemoverSettings {
          attachmentFolderPath: string;
          orphanAttachmentScanMode: string;
          orphanAttachmentScanPaths: string[];
        }

        function isRemoverSettings(value: unknown): value is RemoverSettings {
          const record = value as Record<string, unknown>;
          return typeof value === 'object' && value !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['orphanAttachmentScanMode'] === 'string'
            && Array.isArray(record['orphanAttachmentScanPaths']);
        }

        // The plugin does not expose its settings publicly, so locate the live settings object by
        // Walking the plugin's component tree.
        function findSettings(): null | RemoverSettings {
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
            if (isRemoverSettings(record['settings'])) {
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
          return {
            confirmText: '',
            isKeptAliveAfterScan: false,
            isOrphanGoneAfterScan: false,
            isOrphanKeptWhileModeOff: false,
            modeOffNoticeText: '',
            settingsFound: false
          };
        }
        const settings: RemoverSettings = foundSettings;
        const priorFolderPath = settings.attachmentFolderPath;
        const priorScanMode = settings.orphanAttachmentScanMode;
        const priorScanPaths = settings.orphanAttachmentScanPaths;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const rootFolder = `duo-assets-${stamp}`;
        // Named after a note that does NOT exist. That is the whole scenario: the note was deleted and
        // Its attachment folder was left behind.
        const ownerlessFolder = `${rootFolder}/duo-gone-${stamp}`;
        const liveFolder = `${rootFolder}/duo-live-${stamp}`;
        const orphanPath = `${ownerlessFolder}/lost.png`;
        const keptPath = `${liveFolder}/kept.png`;
        const liveNotePath = `duo-live-${stamp}.md`;
        const createdPaths = [orphanPath, keptPath, liveNotePath];

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone: the sweep trashes
         * entries on its own queue, and trashing one a second time throws `ENOENT` from the rename
         * into `.trash`.
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

        function findModalContentEl(): Element | null {
          return activeDocument.querySelector('.modal-content');
        }

        /**
         * Reads every notice on screen, not just the first.
         *
         * The sweep puts its progress bar up as a notice of its own, so the one that reports the outcome is
         * rarely the first element matching the selector.
         *
         * @returns The text of every notice currently shown.
         */
        function readNoticeTexts(): string {
          return [...activeDocument.querySelectorAll('.notice')].map((noticeEl) => noticeEl.textContent).join(' | ');
        }

        async function confirmTheDialog(): Promise<void> {
          // Confirm through the dialog's own button. Detaching the container would leave the queued
          // Operation's promise unresolved and block everything queued behind it.
          const buttonEls = [...activeDocument.querySelectorAll<HTMLButtonElement>(':scope .modal-content button')];
          const okButtonEl = buttonEls.find((buttonEl) => buttonEl.textContent === 'OK') ?? buttonEls[0];
          okButtonEl?.click();
          await sleep(SETTLE_DELAY_IN_MILLISECONDS);
        }

        try {
          settings.attachmentFolderPath = `./${rootFolder}/\${noteFileName}`;
          settings.orphanAttachmentScanMode = noneMode;
          settings.orphanAttachmentScanPaths = [];

          await app.vault.createFolder(rootFolder);
          await app.vault.createFolder(ownerlessFolder);
          await app.vault.createFolder(liveFolder);
          await app.vault.createBinary(orphanPath, new ArrayBuffer(4));
          await app.vault.createBinary(keptPath, new ArrayBuffer(4));
          // The one live note embeds only `kept.png`. Nothing anywhere references `lost.png`, and no note
          // Resolves to the folder holding it.
          await app.vault.create(liveNotePath, `![[${keptPath}]]\n`);
          await sleep(SETTLE_DELAY_IN_MILLISECONDS);

          await waitUntil({
            message: 'the kept embed was not indexed',
            predicate: () => {
              const keptFile = app.vault.getFileByPath(keptPath);
              return keptFile !== null && app.metadataCache.getBacklinksForFile(keptFile).keys().length > 0;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          /*
           * Sweep one, mode OFF. This is the defect being fixed, asserted as behavior: no dialog appears,
           * because the note-driven scan never even looks inside a folder no note resolves to.
           */
          app.commands.executeCommandById(deleteCommandId);
          try {
            await waitUntil({
              message: 'the sweep with the mode off never reported a result',
              predicate: () => findModalContentEl() !== null || readNoticeTexts().includes('No unused attachments found.'),
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
          } catch {
            /*
             * Not fatal, and deliberately so. The assertion this sweep exists for is that the file SURVIVES
             * it; the wait is only here to keep that from being asserted before the sweep has run. Swallow
             * the timeout, report what was on screen instead, and let the assertions speak.
             */
          }
          const modeOffNoticeText = readNoticeTexts();
          if (findModalContentEl()) {
            // Should not happen; confirm it away rather than leaving a modal blocking the second sweep.
            await confirmTheDialog();
          }
          await sleep(SETTLE_DELAY_IN_MILLISECONDS);
          const isOrphanKeptWhileModeOff = app.vault.getAbstractFileByPath(orphanPath) !== null;

          // Sweep two, mode ON and scoped to the staged tree, so nothing else in the vault is at risk.
          settings.orphanAttachmentScanMode = listedPathsMode;
          settings.orphanAttachmentScanPaths = [rootFolder];

          app.commands.executeCommandById(deleteCommandId);
          await waitUntil({
            message: 'the confirmation dialog never appeared',
            predicate: () => findModalContentEl() !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const confirmText = findModalContentEl()?.textContent ?? '';
          await confirmTheDialog();

          await waitUntil({
            message: 'the ownerless attachment was never trashed',
            predicate: () => app.vault.getAbstractFileByPath(orphanPath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          return {
            confirmText,
            isKeptAliveAfterScan: app.vault.getAbstractFileByPath(keptPath) !== null,
            isOrphanGoneAfterScan: app.vault.getAbstractFileByPath(orphanPath) === null,
            isOrphanKeptWhileModeOff,
            modeOffNoticeText,
            settingsFound: true
          };
        } finally {
          settings.attachmentFolderPath = priorFolderPath;
          settings.orphanAttachmentScanMode = priorScanMode;
          settings.orphanAttachmentScanPaths = priorScanPaths;
          for (const path of createdPaths) {
            await trashIfExists(path);
          }
          await trashIfExists(ownerlessFolder);
          await trashIfExists(liveFolder);
          await trashIfExists(rootFolder);
        }
      },
      input: {
        deleteCommandId: DELETE_COMMAND_ID,
        listedPathsMode: ORPHAN_SCAN_MODE_LISTED_PATHS,
        noneMode: ORPHAN_SCAN_MODE_NONE,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // The gap itself: with the mode off, a whole-vault sweep walks straight past the ownerless folder.
    expect(result.isOrphanKeptWhileModeOff, `notices after the mode-off sweep: ${result.modeOffNoticeText}`).toBe(true);

    // And with the mode on, the same file is found through no note at all.
    expect(result.isOrphanGoneAfterScan).toBe(true);

    // The still-embedded attachment survives the wider pass, so it is discriminating rather than thorough.
    expect(result.isKeptAliveAfterScan).toBe(true);

    expect(result.confirmText).toContain('1 attachment(s) will be moved to the trash.');
    expect(result.confirmText).toContain('lost.png');
    expect(result.confirmText).not.toContain('kept.png');
  }, 180_000);
});
