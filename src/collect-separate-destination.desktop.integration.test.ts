import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #78: `collectedAttachmentFolderPath` must give the
 * `Collect attachments` commands a destination of their own, leaving the one that governs NEWLY
 * inserted attachments alone.
 *
 * The reporter's own workflow is what is staged: a shared `_Attachments` folder while a note is
 * being worked on, and a portable `<note>.assets` folder beside the note once it is collected for
 * export. Two phases over the same shape:
 *   - control (the setting empty) -> collecting uses the new-attachment location, as it always did;
 *   - fix (the setting filled in) -> collecting uses it instead.
 * Both phases also resolve where a NEW attachment would land, which is what proves the two
 * destinations are really decoupled rather than merely both changed.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const NEW_ATTACHMENT_FOLDER_PATH = '_Attachments';
const COLLECTED_ATTACHMENT_FOLDER_PATH = './{{noteFileName}}.assets';
/*
 * Under the transport's ~30s per-closure cap, not at it.
 * The closure spends this ceiling twice per phase and runs two phases, so at 10_000 it declared 40s.
 * The eval is killed at the cap first and reported as a bare transport timeout.
 * That names the harness rather than the wait that overran.
 * Each step is a vault write or a queued collect in a small temp vault, well under a second.
 * The constant feeds nothing but closure input, so no Node-side wait sees the change.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 6000;

interface PhaseResult {
  readonly collectedPath: null | string;
  readonly newAttachmentPath: string;
}

interface ProbeResult {
  readonly control: PhaseResult;
  readonly fix: PhaseResult;
  readonly probesFound: boolean;
}

describe('Collect attachments honors a destination of its own (issue #78)', () => {
  it('collects into the collected-attachment folder while new attachments keep their own', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        collectedAttachmentFolderPath,
        lib: { waitUntil },
        newAttachmentFolderPath,
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface CollectDestinationSettings {
          attachmentFolderPath: string;
          collectedAttachmentFolderPath: string;
          shouldRenameCollectedAttachments: boolean;
        }

        type CollectAttachmentsInAbstractFilesFunction = (this: unknown, abstractFiles: unknown[]) => void;

        function isCollectDestinationSettings(value: unknown): value is CollectDestinationSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['collectedAttachmentFolderPath'] === 'string'
            && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
        }

        const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;

        // The settings are not exposed publicly, so the live object the collector reads is located by
        // walking the plugin's component tree.
        function findSettings(): CollectDestinationSettings | null {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [pluginRecord];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            if (isCollectDestinationSettings(record['settings'])) {
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
        const foundCollect = pluginRecord?.['collectAttachmentsInAbstractFiles'];
        if (!foundSettings || typeof foundCollect !== 'function') {
          const emptyPhase: PhaseResult = { collectedPath: null, newAttachmentPath: '' };
          return { control: emptyPhase, fix: emptyPhase, probesFound: false };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: CollectDestinationSettings = foundSettings;
        const collectAttachmentsInAbstractFiles = foundCollect as CollectAttachmentsInAbstractFilesFunction;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorCollectedFolderPath = settings.collectedAttachmentFolderPath;
        const wasRenamingCollectedAttachments = settings.shouldRenameCollectedAttachments;

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

        async function runPhase(collectedTemplate: string, label: string): Promise<PhaseResult> {
          settings.collectedAttachmentFolderPath = collectedTemplate;

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const noteBaseName = `cd-${label}-${stamp}`;
          const notePath = `${noteBaseName}.md`;
          const imageFileName = `cd-img-${label}-${stamp}.png`;

          try {
            await app.vault.createBinary(imageFileName, new ArrayBuffer(4));
            const note = await app.vault.create(notePath, `![[${imageFileName}]]\n`);

            // The embed must be indexed, or the collector walks a note with no links and moves nothing -
            // which would make this phase report the destination it never reached.
            await waitUntil({
              message: 'the staged embed was not indexed',
              predicate: () => {
                const imageFile = app.vault.getFileByPath(imageFileName);
                return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length > 0;
              },
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            /*
             * Where a NEW attachment for this note would land, asked of the same resolver the editor
             * asks. Read BEFORE the collect, so the collect cannot be what changed it, and with the
             * collect template already set, so a shared implementation would show up here.
             */
            const newAttachmentPath = await app.vault.getAvailablePathForAttachments(`cd-new-${label}-${stamp}`, 'png', note);

            // The public surface rather than the command: the command acts on the ACTIVE file, which
            // would mean opening the note and waiting for the workspace to finish switching to it.
            collectAttachmentsInAbstractFiles.call(pluginRecord, [note]);

            await waitUntil({
              message: 'the staged attachment never left the vault root, so the collect did not run',
              predicate: () => app.vault.getFileByPath(imageFileName) === null,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            const collectedPath = app.vault.getFiles()
              .map((file) => file.path)
              .find((path) => path !== imageFileName && path.endsWith(`/${imageFileName}`)) ?? null;
            return { collectedPath, newAttachmentPath };
          } finally {
            for (const path of [notePath, imageFileName, `${noteBaseName}.assets`]) {
              await trashIfExists(path);
            }
          }
        }

        try {
          settings.attachmentFolderPath = newAttachmentFolderPath;
          // The name must survive the collect, or the moved file could not be found by its own name.
          settings.shouldRenameCollectedAttachments = false;

          const control = await runPhase('', 'control');
          const fix = await runPhase(collectedAttachmentFolderPath, 'fix');
          return { control, fix, probesFound: true };
        } finally {
          await trashIfExists(newAttachmentFolderPath);
          /* eslint-disable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
          settings.attachmentFolderPath = priorFolderPath;
          settings.collectedAttachmentFolderPath = priorCollectedFolderPath;
          settings.shouldRenameCollectedAttachments = wasRenamingCollectedAttachments;
          /* eslint-enable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
        }
      },
      input: {
        collectedAttachmentFolderPath: COLLECTED_ATTACHMENT_FOLDER_PATH,
        newAttachmentFolderPath: NEW_ATTACHMENT_FOLDER_PATH,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // Control: an empty setting means "wherever new attachments go", which is what it always did.
    expect(result.control.collectedPath).toMatch(/^_Attachments\/cd-img-control-.*\.png$/);
    expect(result.control.newAttachmentPath).toMatch(/^_Attachments\/cd-new-control-.*\.png$/);

    // Fix: collecting lands beside the note, and a new attachment still goes to the shared folder.
    expect(result.fix.collectedPath).toMatch(/^cd-fix-.*\.assets\/cd-img-fix-.*\.png$/);
    expect(result.fix.newAttachmentPath).toMatch(/^_Attachments\/cd-new-fix-.*\.png$/);
  }, 180_000);
});
