import type { TFile } from 'obsidian';
import type {
  AttachmentPathContext,
  GetAvailablePathForAttachmentsExtendedFnParams,
  GetAvailablePathForAttachmentsFnExtended
} from 'obsidian-dev-utils/obsidian/attachment-path';

import { evalInObsidian } from 'obsidian-integration-testing';
import { getTempVault } from 'obsidian-integration-testing/vitest-global-setup';
import {
  describe,
  expect,
  it
} from 'vitest';

import {
  FAT_NOTE_LINK_COUNT,
  FAT_NOTE_PATH,
  fatAttachmentPath,
  largeAttachmentPath,
  largeNotePath,
  PERFORMANCE_VAULT_NOTE_COUNT,
  PERFORMANCE_VAULT_TOTAL_FILE_COUNT,
  smallAttachmentPath,
  smallNotePath
} from '../scripts/helpers/generate-performance-vault.ts';

/*
 * Localizes the bulk-deletion bottleneck described in CLAUDE.md "Known Issues". The
 * consumer (`consistent-attachments-and-links`) calls the dev-utils core
 * `getAttachmentFilePath` once per attachment link per file; that core reads the WHOLE
 * binary of each attachment (`await app.vault.readBinary(...)`) before dispatching to this
 * plugin's patched `Vault.getAvailablePathForAttachments.extended` handler. This test
 * reproduces that exact call shape against a pre-populated real vault and decomposes the
 * per-call cost into (a) the binary read and (b) the handler, proving the read — wasted for
 * the default templates, which reference no attachment-content token — is the dominant,
 * size-proportional contributor.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
// The literal context string `consistent-attachments-and-links` passes (files-handler.ts).
const CONSUMER_CONTEXT = 'consistent-attachments-and-links';
const INDEX_WAIT_IN_MS = 180_000;
const INDEX_POLL_IN_MS = 2_000;
const SETTLE_DELAY_IN_MS = 5_000;
const SCENARIO_TIMEOUT_IN_MS = 480_000;
// Warm repeats when isolating the handler-only micro-cost.
const HANDLER_ITERATIONS = 200;
// The content-free handler must not be more than this many times slower than the content-bearing one (passing the binary content buys no useful work).
const CONTENT_WASTE_TOLERANCE = 2;

interface FullConsumerTiming {
  readonly avgFullMs: number;
  readonly avgReadMs: number;
}

interface NoteAttachmentPair {
  readonly attachment: string;
  readonly note: string;
}

interface ResolvedNoteAttachment {
  readonly attachmentFile: TFile;
  readonly noteFile: TFile;
}

const smallPairs: NoteAttachmentPair[] = Array.from(
  { length: PERFORMANCE_VAULT_NOTE_COUNT },
  (_unused, index) => ({ attachment: smallAttachmentPath(index), note: smallNotePath(index) })
);
const largePairs: NoteAttachmentPair[] = Array.from(
  { length: PERFORMANCE_VAULT_NOTE_COUNT },
  (_unused, index) => ({ attachment: largeAttachmentPath(index), note: largeNotePath(index) })
);
const fatAttachmentPaths: string[] = Array.from({ length: FAT_NOTE_LINK_COUNT }, (_unused, index) => fatAttachmentPath(index));

describe('Attachment-path bottleneck', () => {
  it('attributes the per-call cost to the wasted binary read, not the handler', async () => {
    const result = await evalInObsidian({
      args: {
        CONSUMER_CONTEXT,
        EXPECTED_FILE_COUNT: PERFORMANCE_VAULT_TOTAL_FILE_COUNT,
        FAT_NOTE_PATH,
        fatAttachmentPaths,
        HANDLER_ITERATIONS,
        INDEX_POLL_IN_MS,
        INDEX_WAIT_IN_MS,
        largePairs,
        PLUGIN_ID,
        SETTLE_DELAY_IN_MS,
        smallPairs
      },
      async fn({
        app,
        CONSUMER_CONTEXT: consumerContext,
        EXPECTED_FILE_COUNT: expectedFileCount,
        FAT_NOTE_PATH: fatNotePath,
        fatAttachmentPaths: fatAttachments,
        HANDLER_ITERATIONS: handlerIterations,
        INDEX_POLL_IN_MS: pollMs,
        INDEX_WAIT_IN_MS: waitMs,
        largePairs: largeNotes,
        PLUGIN_ID: pluginId,
        SETTLE_DELAY_IN_MS: settleMs,
        smallPairs: smallNotes
      }) {
        const EMPTY_RESULT = {
          error: null as null | string,
          extendedNoContentMs: -1,
          extendedWithContentMs: -1,
          fatNoteExtendedMs: -1,
          fileCount: -1,
          largeAvgFullMs: -1,
          largeAvgReadMs: -1,
          smallAvgFullMs: -1,
          smallAvgReadMs: -1,
          thinNoteExtendedMs: -1
        };

        if (!app.plugins.getPlugin(pluginId)) {
          return { ...EMPTY_RESULT, error: 'Plugin not loaded' };
        }

        const context = consumerContext as AttachmentPathContext;
        const extendedFn = (app.vault.getAvailablePathForAttachments as Partial<GetAvailablePathForAttachmentsFnExtended>).extended;
        if (!extendedFn) {
          return { ...EMPTY_RESULT, error: 'Patched getAvailablePathForAttachments.extended is not installed' };
        }
        // Bind the narrowed (non-undefined) handler so the hoisted timing helpers can invoke it.
        const invokeExtended = extendedFn;

        // Wait for Obsidian's startup scan to index the whole pre-populated vault.
        const deadline = Date.now() + waitMs;
        let fileCount = app.vault.getFiles().length;
        while (fileCount < expectedFileCount && Date.now() < deadline) {
          await sleep(pollMs);
          fileCount = app.vault.getFiles().length;
        }
        // Let the metadata cache resolve the embeds so the handler's link walk is realistic.
        await sleep(settleMs);

        const small = await timeFullConsumer(smallNotes);
        const large = await timeFullConsumer(largeNotes);

        // Isolate the handler micro-cost on one large attachment: with vs without content.
        const largeSamplePair = largeNotes[0];
        const handlerSample = largeSamplePair ? resolvePair(largeSamplePair) : null;
        if (!handlerSample) {
          return { ...EMPTY_RESULT, error: 'Could not resolve the large handler sample', fileCount };
        }
        const handlerContent = await app.vault.readBinary(handlerSample.attachmentFile);
        const extendedWithContentMs = await timeExtended(handlerSample.noteFile, handlerSample.attachmentFile, handlerContent);
        const extendedNoContentMs = await timeExtended(handlerSample.noteFile, handlerSample.attachmentFile, undefined);

        // Link-count effect: the fat note (many embeds) vs a thin note (one embed).
        const fatNote = app.vault.getFileByPath(fatNotePath);
        const fatAttachment = app.vault.getFileByPath(fatAttachments[0] ?? '');
        const thinSamplePair = smallNotes[0];
        const thinSample = thinSamplePair ? resolvePair(thinSamplePair) : null;
        if (!fatNote || !fatAttachment || !thinSample) {
          return { ...EMPTY_RESULT, error: 'Could not resolve fat/thin link-count samples', fileCount };
        }
        const fatContent = await app.vault.readBinary(fatAttachment);
        const thinContent = await app.vault.readBinary(thinSample.attachmentFile);
        const fatNoteExtendedMs = await timeExtended(fatNote, fatAttachment, fatContent);
        const thinNoteExtendedMs = await timeExtended(thinSample.noteFile, thinSample.attachmentFile, thinContent);

        return {
          error: null,
          extendedNoContentMs,
          extendedWithContentMs,
          fatNoteExtendedMs,
          fileCount,
          largeAvgFullMs: large.avgFullMs,
          largeAvgReadMs: large.avgReadMs,
          smallAvgFullMs: small.avgFullMs,
          smallAvgReadMs: small.avgReadMs,
          thinNoteExtendedMs
        };

        function resolvePair(pair: NoteAttachmentPair): null | ResolvedNoteAttachment {
          const noteFile = app.vault.getFileByPath(pair.note);
          const attachmentFile = app.vault.getFileByPath(pair.attachment);
          if (!noteFile || !attachmentFile) {
            return null;
          }
          return { attachmentFile, noteFile };
        }

        function buildParams(noteFile: TFile, attachmentFile: TFile, content: ArrayBuffer | undefined): GetAvailablePathForAttachmentsExtendedFnParams {
          return {
            attachmentFileBaseName: attachmentFile.basename,
            attachmentFileExtension: attachmentFile.extension,
            attachmentFileStats: attachmentFile.stat,
            context,
            notePathOrFile: noteFile.path,
            oldAttachmentPathOrFile: attachmentFile.path,
            readAttachmentFileContent: content ? (): Promise<ArrayBuffer> => Promise.resolve(content) : null,
            shouldSkipDuplicateCheck: true,
            shouldSkipMissingAttachmentFolderCreation: true
          };
        }

        async function timeFullConsumer(pairs: NoteAttachmentPair[]): Promise<FullConsumerTiming> {
          let readMs = 0;
          let fullMs = 0;
          let count = 0;
          for (const pair of pairs) {
            const resolved = resolvePair(pair);
            if (!resolved) {
              continue;
            }
            const start = performance.now();

            const content = await app.vault.readBinary(resolved.attachmentFile);
            const afterRead = performance.now();

            await invokeExtended(buildParams(resolved.noteFile, resolved.attachmentFile, content));
            const afterExtended = performance.now();
            readMs += afterRead - start;
            fullMs += afterExtended - start;
            count++;
          }
          const safeCount = count || 1;
          return { avgFullMs: fullMs / safeCount, avgReadMs: readMs / safeCount };
        }

        async function timeExtended(noteFile: TFile, attachmentFile: TFile, content: ArrayBuffer | undefined): Promise<number> {
          const params = buildParams(noteFile, attachmentFile, content);
          const start = performance.now();
          for (let iteration = 0; iteration < handlerIterations; iteration++) {
            await invokeExtended(params);
          }
          return (performance.now() - start) / handlerIterations;
        }
      },
      vaultPath: getTempVault().path
    });

    // Surface the full decomposition so a run reads as a diagnosis, not just a pass/fail.
    // `console.warn` is the only console level the lint config permits here, and it keeps the breakdown visible on a passing run.
    console.warn('Attachment-path bottleneck breakdown (ms):', result);

    expect(result.error).toBeNull();
    // The pre-populated vault really was fully indexed before timing.
    expect(result.fileCount).toBeGreaterThanOrEqual(PERFORMANCE_VAULT_TOTAL_FILE_COUNT);

    // KEY FINDING: the consumer call cost grows with attachment file size although the produced path is identical, so the size-proportional binary read dominates, not the path computation.
    expect(result.largeAvgFullMs).toBeGreaterThan(result.smallAvgFullMs);

    // The binary read itself scales with attachment size.
    expect(result.largeAvgReadMs).toBeGreaterThan(result.smallAvgReadMs);

    // For large attachments the wasted read alone costs more than the entire handler.
    expect(result.largeAvgReadMs).toBeGreaterThan(result.extendedWithContentMs);

    // Passing the binary content buys no useful work (no default token reads it): the handler
    // Is about as fast without it, so reading it is pure waste.
    expect(result.extendedNoContentMs).toBeLessThan(result.extendedWithContentMs * CONTENT_WASTE_TOLERANCE);

    // Secondary cost surfaced for the record: the handler's per-call cache + link walk is at
    // Least as expensive for a note with many embeds as for a note with one.
    expect(result.fatNoteExtendedMs).toBeGreaterThan(0);
    expect(result.thinNoteExtendedMs).toBeGreaterThan(0);
  }, SCENARIO_TIMEOUT_IN_MS);
});
