import type { PopulateFilesParams } from 'obsidian-integration-testing';

/**
 * @file
 *
 * Builds the file map for the `integration-tests:desktop-performance` vault used by
 * `attachment-path-bottleneck.desktop-performance.integration.test.ts`. The vault holds
 * many notes that embed real binary attachments, so the per-call cost of resolving an
 * attachment path (which the dev-utils core pays via `Vault.readBinary`) can be measured
 * and decomposed against attachment file size and note link count.
 */

/**
 * Extension used for every generated attachment. A non-markdown extension so Obsidian
 * treats the files as attachments rather than notes.
 */
export const ATTACHMENT_EXTENSION = 'png';

/**
 * Folder holding the small-attachment notes (one note embeds one small attachment).
 */
export const SMALL_FOLDER = 'small';

/**
 * Folder holding the large-attachment notes (one note embeds one large attachment).
 */
export const LARGE_FOLDER = 'large';

/**
 * Folder holding the single fat note and the attachments it embeds.
 */
export const FAT_FOLDER = 'fat';

/**
 * Path of the single fat note that embeds {@link FAT_NOTE_LINK_COUNT} attachments, used to
 * measure how the handler's per-call `getCacheSafe` + `getAllLinks` walk scales with the
 * number of links in the embedding note.
 */
export const FAT_NOTE_PATH = `${FAT_FOLDER}/fat-note.md`;

const BYTES_PER_KILOBYTE = 1024;
const LARGE_ATTACHMENT_KILOBYTES = 512;

/**
 * Size of each small attachment, in bytes.
 */
export const SMALL_ATTACHMENT_SIZE_IN_BYTES = BYTES_PER_KILOBYTE;

/**
 * Size of each large attachment, in bytes. Far larger than the small attachment so that a
 * size-proportional `readBinary` is the dominant, unmistakable contributor to the per-call
 * cost when comparing the two buckets.
 */
export const LARGE_ATTACHMENT_SIZE_IN_BYTES = LARGE_ATTACHMENT_KILOBYTES * BYTES_PER_KILOBYTE;

/**
 * How many notes are generated in each of the small and large buckets. Overridable via the
 * `CAL_PERF_NOTE_COUNT` environment variable for bounded local runs.
 */
const DEFAULT_NOTE_COUNT = 100;
export const PERFORMANCE_VAULT_NOTE_COUNT = Number(process.env['CAL_PERF_NOTE_COUNT']) || DEFAULT_NOTE_COUNT;

/**
 * How many attachments the single fat note embeds.
 */
export const FAT_NOTE_LINK_COUNT = 200;

// Each note index contributes a small note, a small attachment, a large note, and a large attachment.
const FILES_PER_NOTE_INDEX = 4;
const FAT_NOTE_FILE_COUNT = 1;

/**
 * Total number of vault files the generator writes (notes + attachments). Tests wait for
 * Obsidian's index to reach this count before measuring.
 */
export const PERFORMANCE_VAULT_TOTAL_FILE_COUNT = PERFORMANCE_VAULT_NOTE_COUNT * FILES_PER_NOTE_INDEX + FAT_NOTE_LINK_COUNT + FAT_NOTE_FILE_COUNT;

/**
 * Returns the vault-relative path of the fat-note attachment at the given index.
 *
 * @param index - The attachment index.
 * @returns The attachment path.
 */
export function fatAttachmentPath(index: number): string {
  return `${FAT_FOLDER}/fat-att-${String(index)}.${ATTACHMENT_EXTENSION}`;
}

/**
 * Builds the file map for the performance vault, written to disk by `TempVault.populate()`
 * before Obsidian opens it (so its startup scan indexes everything in one pass).
 *
 * @returns A map of vault-relative paths to content.
 */
export function generatePerformanceVault(): PopulateFilesParams {
  const files: PopulateFilesParams = {};

  for (let index = 0; index < PERFORMANCE_VAULT_NOTE_COUNT; index++) {
    files[smallNotePath(index)] = embed(smallAttachmentPath(index));
    files[smallAttachmentPath(index)] = makeBytes(SMALL_ATTACHMENT_SIZE_IN_BYTES);
    files[largeNotePath(index)] = embed(largeAttachmentPath(index));
    files[largeAttachmentPath(index)] = makeBytes(LARGE_ATTACHMENT_SIZE_IN_BYTES);
  }

  let fatNoteContent = '';
  for (let index = 0; index < FAT_NOTE_LINK_COUNT; index++) {
    files[fatAttachmentPath(index)] = makeBytes(SMALL_ATTACHMENT_SIZE_IN_BYTES);
    fatNoteContent += embed(fatAttachmentPath(index));
  }
  files[FAT_NOTE_PATH] = fatNoteContent;

  return files;

  function embed(attachmentPath: string): string {
    const baseName = attachmentPath.split('/').at(-1) ?? attachmentPath;
    return `![[${baseName}]]\n`;
  }

  function makeBytes(size: number): Uint8Array {
    return new Uint8Array(size).fill(1);
  }
}

/**
 * Returns the vault-relative path of the large attachment at the given index.
 *
 * @param index - The attachment index.
 * @returns The attachment path.
 */
export function largeAttachmentPath(index: number): string {
  return `${LARGE_FOLDER}/large-att-${String(index)}.${ATTACHMENT_EXTENSION}`;
}

/**
 * Returns the vault-relative path of the large note at the given index.
 *
 * @param index - The note index.
 * @returns The note path.
 */
export function largeNotePath(index: number): string {
  return `${LARGE_FOLDER}/note-${String(index)}.md`;
}

/**
 * Returns the vault-relative path of the small attachment at the given index.
 *
 * @param index - The attachment index.
 * @returns The attachment path.
 */
export function smallAttachmentPath(index: number): string {
  return `${SMALL_FOLDER}/small-att-${String(index)}.${ATTACHMENT_EXTENSION}`;
}

/**
 * Returns the vault-relative path of the small note at the given index.
 *
 * @param index - The note index.
 * @returns The note path.
 */
export function smallNotePath(index: number): string {
  return `${SMALL_FOLDER}/note-${String(index)}.md`;
}
