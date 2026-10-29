import type { TFile } from 'obsidian';

import {
  evalInObsidian,
  pollInObsidian
} from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { CustomAttachmentLocationApi } from '../plugin-api/plugin-api.ts';

import {
  FAT_NOTE_LINK_COUNT,
  FAT_NOTE_PATH,
  PERFORMANCE_VAULT_TOTAL_FILE_COUNT
} from '../../scripts/helpers/generate-performance-vault.ts';

/*
 * The shape of `Consistent Attachments and Links`' `Check vault consistency`: it asks where each attachment of a note
 * belongs, once per reference, as a query (no duplicate check, no folder creation). Each answer walks the note's links
 * to number its attachments, so a note with `k` attachment links used to cost `k²` link resolutions, each a
 * vault-wide name lookup — 692 s on a 37,000-note vault. The resolutions are counted rather than timed, so the bound
 * holds on a loaded machine.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const INDEX_WAIT_IN_MS = 180_000;
const INDEX_POLL_IN_MS = 2000;
const SETTLE_DELAY_IN_MS = 5000;
const SCENARIO_TIMEOUT_IN_MS = 480_000;
const PROBE_FILE_PATH = 'audit-burst-probe/probe.md';

describe('Attachment-path audit burst', () => {
  it('resolves a note\'s links once for a burst of questions about it, and again after a vault change', async () => {
    await pollInObsidian({
      intervalInMilliseconds: INDEX_POLL_IN_MS,
      poll: ({ app }) => app.vault.getFiles().length,
      timeoutInMilliseconds: INDEX_WAIT_IN_MS,
      timeoutMessage: `The vault was not indexed within ${String(INDEX_WAIT_IN_MS)} ms`,
      until: (fileCount) => fileCount >= PERFORMANCE_VAULT_TOTAL_FILE_COUNT,
      vaultPath: getTemporaryVault().path
    });

    const result = await evalInObsidian({
      async callback({ app, FAT_NOTE_PATH: fatNotePath, PLUGIN_ID: pluginId, PROBE_FILE_PATH: probeFilePath, SETTLE_DELAY_IN_MS: settleMs }) {
        interface ApiRecord {
          readonly api: unknown;
          readonly isRevoked: boolean;
        }

        interface ObsidianLibWrapper {
          readonly __obsidianLib: ObsidianLibState;
        }

        interface ObsidianLibState {
          readonly pluginApiRegistry?: RegistryWrapper;
        }

        interface RegistryWrapper {
          readonly value?: RegistryValue;
        }

        interface RegistryValue {
          readonly records?: Record<string, ApiRecord[]>;
        }

        const EMPTY_RESULT = {
          afterChangeResolutionCount: -1,
          afterEditResolutionCount: -1,
          burstMs: -1,
          burstResolutionCount: -1,
          error: null as null | string,
          questionCount: -1
        };

        const api = (window as Partial<ObsidianLibWrapper>).__obsidianLib?.pluginApiRegistry?.value?.records?.[pluginId]
          ?.find((candidate) => !candidate.isRevoked)?.api as CustomAttachmentLocationApi | undefined;
        const fatNote = app.vault.getFileByPath(fatNotePath);
        if (!api || !fatNote) {
          return { ...EMPTY_RESULT, error: api ? 'The fat note is missing' : 'The plugin API is not published' };
        }

        // Let the metadata cache resolve the embeds, so the walk sees every link.
        await sleep(settleMs);
        const attachments = (app.metadataCache.getFileCache(fatNote)?.embeds ?? [])
          .map((embed) => app.metadataCache.getFirstLinkpathDest(embed.link, fatNote.path))
          .filter((file) => file !== null);

        // Every link resolution `extractReferenceFile` makes ends here, so counting its calls counts the walk's work.
        const metadataCache = app.metadataCache;
        const resolveLinkOriginal = metadataCache.getFirstLinkpathDest.bind(metadataCache);
        let resolutionCount = 0;
        // eslint-disable-next-line unicorn/name-replacements -- `getFirstLinkpathDest` is Obsidian's own spelling; the counter has to answer to it.
        metadataCache.getFirstLinkpathDest = (linkpath: string, sourcePath: string): ReturnType<typeof resolveLinkOriginal> => {
          resolutionCount++;
          return resolveLinkOriginal(linkpath, sourcePath);
        };

        async function countResolutions(questions: readonly TFile[]): Promise<number> {
          const before = resolutionCount;
          await askAbout(questions);
          return resolutionCount - before;
        }

        async function askAbout(questions: readonly TFile[]): Promise<void> {
          for (const attachment of questions) {
            await api?.getAvailablePathForAttachments({
              attachmentFileBaseName: attachment.basename,
              attachmentFileExtension: attachment.extension,
              attachmentFileStats: attachment.stat,
              context: 'Unknown',
              notePathOrFile: fatNote?.path ?? '',
              oldAttachmentPathOrFile: attachment.path,
              readAttachmentFileContent: null,
              shouldSkipDuplicateCheck: true,
              shouldSkipMissingAttachmentFolderCreation: true
            });
          }
        }

        try {
          const start = performance.now();
          const burstResolutionCount = await countResolutions(attachments);
          const burstMs = performance.now() - start;

          // A file appearing can change what a link resolves to, so the next question resolves afresh.
          await app.vault.createFolder('audit-burst-probe').catch(() => undefined);
          await app.vault.create(probeFilePath, '');
          const afterChangeResolutionCount = await countResolutions(attachments);

          // So does an edit of the note itself: its cache is recomputed, and `changed` fires before the walk.
          await app.vault.append(fatNote, '\n');
          const afterEditResolutionCount = await countResolutions(attachments.slice(0, 1));

          return { afterChangeResolutionCount, afterEditResolutionCount, burstMs, burstResolutionCount, error: null, questionCount: attachments.length };
        } finally {
          // eslint-disable-next-line unicorn/name-replacements -- `getFirstLinkpathDest` is Obsidian's own spelling.
          metadataCache.getFirstLinkpathDest = resolveLinkOriginal;
          const probeFolder = app.vault.getFolderByPath('audit-burst-probe');
          if (probeFolder) {
            await app.fileManager.trashFile(probeFolder);
          }
        }
      },
      input: {
        FAT_NOTE_PATH,
        PLUGIN_ID,
        PROBE_FILE_PATH,
        SETTLE_DELAY_IN_MS
      },
      vaultPath: getTemporaryVault().path
    });

    // `console.warn` is the only console level the lint config permits here, and it keeps the numbers visible on a pass.
    console.warn('Attachment-path audit burst:', result);

    expect(result.error).toBeNull();
    expect(result.questionCount).toBe(FAT_NOTE_LINK_COUNT);
    // One walk of the note for the whole burst, plus slack for the resolver's own lookups. The quadratic walk this
    // replaces made FAT_NOTE_LINK_COUNT² of them.
    expect(result.burstResolutionCount).toBeGreaterThanOrEqual(FAT_NOTE_LINK_COUNT);
    expect(result.burstResolutionCount).toBeLessThanOrEqual(FAT_NOTE_LINK_COUNT * 2);
    // The vault change invalidated the remembered walk, and the burst after it walked the note once more.
    expect(result.afterChangeResolutionCount).toBeGreaterThanOrEqual(FAT_NOTE_LINK_COUNT);
    expect(result.afterChangeResolutionCount).toBeLessThanOrEqual(FAT_NOTE_LINK_COUNT * 2);
    // The edit invalidated it too: one question walked the whole note again.
    expect(result.afterEditResolutionCount).toBeGreaterThanOrEqual(FAT_NOTE_LINK_COUNT);
  }, SCENARIO_TIMEOUT_IN_MS);
});
