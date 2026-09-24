import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for `Collect attachments automatically`, the setting Consistent Attachments and Links
 * hands over when it stops collecting.
 *
 * It drives the REAL flow: the live setting is turned on and the note is changed with a genuine
 * `vault.modify`, so the plugin's own `metadataCache` `changed` handler starts the collect. Two phases:
 *
 *   - misplaced -> an attachment sitting at the vault root is collected into the note's folder;
 *   - parked -> an attachment already in the note's folder under a duplicate suffix, because a different
 *     file holds the proper name, stays exactly where it is. Before the fix, each collect moved it to the
 *     next free suffix, the move rewrote the note, and that change started the next collect, so the file was
 *     renamed without end.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const ATTACHMENT_FOLDER_ROOT = '_AutoCollect';
/*
 * Under the transport's ~30s per-closure cap, not at it. Each phase is its own closure, spending the wait at
 * most twice plus the settle. Indexing one note and collecting one attachment in a small temp vault take well
 * under a second.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 8000;
// Long enough for a still-looping collect to rename the parked file several times over.
const SETTLE_IN_MILLISECONDS = 4000;

type Phase = 'misplaced' | 'parked';

interface PhaseResult {
  readonly filePaths: readonly string[];
  readonly settingsFound: boolean;
}

async function runPhase(phase: Phase): Promise<PhaseResult> {
  return await evalInObsidian({
    async callback({
      app,
      attachmentFolderRoot,
      lib: { waitUntil },
      phaseName,
      pluginId,
      settleInMilliseconds,
      waitTimeoutInMilliseconds
    }): Promise<PhaseResult> {
      interface AutoCollectSettings {
        attachmentFolderPath: string;
        collectedAttachmentFileName: string;
        collectedAttachmentFolderPath: string;
        shouldCollectAttachmentsAutomatically: boolean;
        shouldRenameCollectedAttachments: boolean;
      }

      function isAutoCollectSettings(value: unknown): value is AutoCollectSettings {
        const record = value as null | Record<string, unknown>;
        return typeof value === 'object' && record !== null
          && typeof record['attachmentFolderPath'] === 'string'
          && typeof record['collectedAttachmentFileName'] === 'string'
          && typeof record['collectedAttachmentFolderPath'] === 'string'
          && typeof record['shouldCollectAttachmentsAutomatically'] === 'boolean'
          && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
      }

      const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;

      // The settings are not exposed publicly, so the live object the component reads is located by
      // walking the plugin's component tree.
      function findSettings(): AutoCollectSettings | null {
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
          if (isAutoCollectSettings(record['settings'])) {
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
        return { filePaths: [], settingsFound: false };
      }

      const prior = { ...settings };
      const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
      const noteStem = `auto-${phaseName}-${stamp}`;
      const notePath = `${noteStem}.md`;
      const noteFolderPath = `${attachmentFolderRoot}/${noteStem}`;

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

      function listNoteFolder(): string[] {
        const folder = app.vault.getFolderByPath(noteFolderPath);
        return folder ? folder.children.map((child) => child.path).sort() : [];
      }

      try {
        settings.attachmentFolderPath = `${attachmentFolderRoot}/{{noteFileName}}`;
        settings.collectedAttachmentFolderPath = '';
        settings.shouldCollectAttachmentsAutomatically = false;

        /*
         * Every phase embeds one attachment misplaced at the vault root, and waits for it to leave. That is the
         * proof a collect actually ran, so the parked phase cannot pass merely because nothing happened yet.
         */
        const misplacedPath = `${noteStem}-img.png`;
        const embeddedPaths: string[] = [];
        if (phaseName === 'misplaced') {
          settings.shouldRenameCollectedAttachments = false;
          settings.collectedAttachmentFileName = '';
        } else {
          settings.shouldRenameCollectedAttachments = true;
          settings.collectedAttachmentFileName = 'pic';
          await app.vault.createFolder(noteFolderPath);
          // A DIFFERENT file holds the proper name, so the referenced one is parked beside it.
          await app.vault.createBinary(`${noteFolderPath}/pic.png`, new ArrayBuffer(3));
          const parkedPath = `${noteFolderPath}/pic 1.png`;
          await app.vault.createBinary(parkedPath, new ArrayBuffer(4));
          embeddedPaths.push(parkedPath);
        }

        await app.vault.createBinary(misplacedPath, new ArrayBuffer(5));
        embeddedPaths.push(misplacedPath);
        const embeds = embeddedPaths.map((path) => `![[${path}]]`).join('\n');
        const note = await app.vault.create(notePath, `${embeds}\n`);
        await waitUntil({
          message: 'the staged embeds were not indexed',
          predicate: () =>
            embeddedPaths.every((path) => {
              const embeddedFile = app.vault.getFileByPath(path);
              return embeddedFile !== null && app.metadataCache.getBacklinksForFile(embeddedFile).keys().length > 0;
            }),
          timeoutInMilliseconds: waitTimeoutInMilliseconds
        });

        // Turned on only now, so creating the note did not already collect it.
        settings.shouldCollectAttachmentsAutomatically = true;
        await app.vault.modify(note, `Changed.\n\n${embeds}\n`);

        await waitUntil({
          message: 'the misplaced attachment was not collected automatically',
          predicate: () => app.vault.getFileByPath(misplacedPath) === null,
          timeoutInMilliseconds: waitTimeoutInMilliseconds
        });

        await sleep(settleInMilliseconds);
        return { filePaths: listNoteFolder(), settingsFound: true };
      } finally {
        settings.shouldCollectAttachmentsAutomatically = false;
        await trashIfExists(notePath);
        await trashIfExists(noteFolderPath);
        settings.attachmentFolderPath = prior.attachmentFolderPath;
        settings.collectedAttachmentFileName = prior.collectedAttachmentFileName;
        settings.collectedAttachmentFolderPath = prior.collectedAttachmentFolderPath;
        settings.shouldCollectAttachmentsAutomatically = prior.shouldCollectAttachmentsAutomatically;
        settings.shouldRenameCollectedAttachments = prior.shouldRenameCollectedAttachments;
      }
    },
    input: {
      attachmentFolderRoot: ATTACHMENT_FOLDER_ROOT,
      phaseName: phase,
      pluginId: PLUGIN_ID,
      settleInMilliseconds: SETTLE_IN_MILLISECONDS,
      waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
    },
    vaultPath: getTemporaryVault().path
  });
}

describe('Collect attachments automatically', () => {
  it('collects a misplaced attachment when its note changes', async () => {
    const result = await runPhase('misplaced');

    expect(result.settingsFound).toBe(true);
    expect(result.filePaths).toHaveLength(1);
    expect(result.filePaths[0]).toMatch(/-img\.png$/u);
  }, 60_000);

  it('leaves an attachment parked under a duplicate suffix where it is, rather than renaming it without end', async () => {
    const result = await runPhase('parked');

    expect(result.settingsFound).toBe(true);
    /*
     * `pic 1.png` is where it was staged. The misplaced one, renamed to `pic` like every collected file here,
     * found both `pic.png` and `pic 1.png` taken and parked at `pic 2.png`, where it stays too. A loop would
     * have moved the parked files on to later suffixes.
     */
    expect(result.filePaths.map((path) => path.split('/').at(-1))).toEqual(['pic 1.png', 'pic 2.png', 'pic.png']);
  }, 60_000);
});
