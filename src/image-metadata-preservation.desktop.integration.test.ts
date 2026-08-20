import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #55 (G97): converting an image to JPEG re-encodes it through a
 * canvas, which keeps only the pixels — so EXIF, GPS and the rest are dropped by construction. The
 * requester plots photos on a map from their EXIF geolocation, and that stops working once OCAL has
 * converted them.
 *
 * This drives the real clipboard `insertFiles` sink with a genuine, decodable JPEG carrying a known
 * EXIF block, and reads the saved attachment back out of the vault. It asserts the block survives
 * with the setting on and does not with it off, and that the orientation tag is reset to upright —
 * the canvas has already applied the original rotation to the pixels, so carrying the tag across
 * verbatim would rotate the image a second time.
 */

interface AdapterWithFsPromises {
  fsPromises: FsPromisesLike;
}

interface ExifTags {
  hasMake: boolean;
  orientation: number;
}

interface FsPromisesLike {
  unlink(path: string): Promise<void>;
  writeFile(path: string, data: Uint8Array): Promise<void>;
}

interface InsertFilesClipboardManager {
  insertFiles(importedAttachments: unknown[]): Promise<void>;
}

interface MarkdownEditModeLike {
  clipboardManager?: InsertFilesClipboardManager;
}

interface MarkdownViewLike {
  editMode?: MarkdownEditModeLike;
}

interface MetadataRoundTripResult {
  readonly makeSurvived: boolean;
  readonly orientation: number;
  readonly savedPath: string;
  readonly settingsFound: boolean;
  readonly sourceHadMake: boolean;
  readonly sourceOrientation: number;
}

interface OsModuleLike {
  tmpdir(): string;
}

interface PathModuleLike {
  join(...parts: string[]): string;
}

/*
 * Desktop-only: no Android emulator is available in this environment. The conversion path is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to Android
 * once an emulator exists.
 */

describe('Image metadata is preserved across the JPEG conversion (issue #55)', () => {
  async function roundTrip(shouldPreserveImageMetadata: boolean): Promise<MetadataRoundTripResult> {
    return await evalInObsidian({
      async callback({ app, shouldPreserveImageMetadata: shouldPreserve }): Promise<MetadataRoundTripResult> {
        interface ConversionSettings {
          attachmentFolderPath: string;
          convertImagesToJpegMode: string;
          isPathIgnored(path: string): boolean;
          jpegQuality: number;
          shouldPreserveImageMetadata: boolean;
        }

        const MARKER_PREFIX = 0xFF;
        const APP1_MARKER = 0xE1;
        const SOS_MARKER = 0xDA;
        const EOI_MARKER = 0xD9;
        const BYTE_BASE = 256;
        const EXIF_HEADER = 'Exif\0\0';
        const MAKE_TAG = 0x01_0F;
        const ORIENTATION_TAG = 0x01_12;
        const ROTATED_180 = 3;
        const MAKE_VALUE = 'OCAL';

        function bytesOf(text: string): number[] {
          return Array.from(text, (character) => character.codePointAt(0) ?? 0);
        }

        function lowByte(value: number): number {
          return value % BYTE_BASE;
        }

        function highByte(value: number): number {
          return Math.floor(value / BYTE_BASE) % BYTE_BASE;
        }

        /*
         * A little-endian TIFF block holding two IFD0 entries: `Make`, an arbitrary tag that must be
         * carried across untouched, and `Orientation`, the one tag that must NOT be.
         */
        function exifPayload(): number[] {
          const TIFF_HEADER = [0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00];
          const ENTRY_COUNT = [0x02, 0x00];
          const ASCII_TYPE = 2;
          const SHORT_TYPE = 3;
          const MAKE_ENTRY = [
            lowByte(MAKE_TAG),
            highByte(MAKE_TAG),
            ASCII_TYPE,
            0x00,
            0x04,
            0x00,
            0x00,
            0x00,
            ...bytesOf(MAKE_VALUE)
          ];
          const ORIENTATION_ENTRY = [
            lowByte(ORIENTATION_TAG),
            highByte(ORIENTATION_TAG),
            SHORT_TYPE,
            0x00,
            0x01,
            0x00,
            0x00,
            0x00,
            ROTATED_180,
            0x00,
            0x00,
            0x00
          ];
          const NEXT_IFD = [0x00, 0x00, 0x00, 0x00];
          return [...bytesOf(EXIF_HEADER), ...TIFF_HEADER, ...ENTRY_COUNT, ...MAKE_ENTRY, ...ORIENTATION_ENTRY, ...NEXT_IFD];
        }

        /*
         * A genuine JPEG the canvas can decode — produced by the canvas itself — with the EXIF block
         * spliced in right after the `SOI`. A hand-rolled byte sequence would not decode, and this
         * test is worthless unless the conversion really runs.
         */
        function createJpegWithExif(): ArrayBuffer {
          const SIZE = 8;
          // Detached: this canvas is a JPEG encoder, not UI.
          const canvas = createEl('canvas');
          canvas.width = SIZE;
          canvas.height = SIZE;
          const context = canvas.getContext('2d');
          if (!context) {
            throw new Error('Could not get 2D context.');
          }
          context.fillStyle = '#4488cc';
          context.fillRect(0, 0, SIZE, SIZE);
          const base64 = canvas.toDataURL('image/jpeg', 0.9).split(';base64,', 2)[1] ?? '';
          const raw = atob(base64);
          const jpeg = new Uint8Array(raw.length);
          for (let index = 0; index < raw.length; index++) {
            // eslint-disable-next-line unicorn/prefer-code-point -- `raw` is a binary string, one byte per code unit. `codePointAt` would combine a surrogate pair into a value above 255 and consume two positions.
            jpeg[index] = raw.charCodeAt(index);
          }

          const payload = exifPayload();
          const LENGTH_SIZE = 2;
          const length = payload.length + LENGTH_SIZE;
          const segment = [MARKER_PREFIX, APP1_MARKER, highByte(length), lowByte(length), ...payload];
          const SOI_SIZE = 2;
          const result = new Uint8Array(jpeg.length + segment.length);
          result.set(jpeg.subarray(0, SOI_SIZE), 0);
          result.set(segment, SOI_SIZE);
          result.set(jpeg.subarray(SOI_SIZE), SOI_SIZE + segment.length);
          return result.buffer;
        }

        /*
         * Walks the JPEG's segment chain looking for the EXIF `APP1`, and reads the two tags back out
         * of its IFD0. Returns `-1` for an orientation it cannot find, so a missing block and an
         * upright one stay distinguishable.
         */
        function readExif(bytes: Uint8Array): ExifTags {
          const SEGMENT_LENGTH_SIZE = 2;
          const SEGMENT_HEADER_SIZE = 4;
          const IFD_ENTRY_SIZE = 12;
          const IFD_ENTRY_VALUE_OFFSET = 8;
          const header = bytesOf(EXIF_HEADER);
          let offset = 2;
          while (offset + SEGMENT_HEADER_SIZE <= bytes.length) {
            if (bytes[offset] !== MARKER_PREFIX) {
              break;
            }
            const marker = bytes[offset + 1];
            if (marker === SOS_MARKER || marker === EOI_MARKER) {
              break;
            }
            const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
            const segmentLength = view.getUint16(offset + SEGMENT_LENGTH_SIZE);
            const payloadOffset = offset + SEGMENT_HEADER_SIZE;
            const isExif = marker === APP1_MARKER
              && header.every((byte, index) => bytes[payloadOffset + index] === byte);
            if (isExif) {
              const tiffOffset = payloadOffset + header.length;
              const ifdOffset = tiffOffset + view.getUint32(tiffOffset + 4, true);
              const entryCount = view.getUint16(ifdOffset, true);
              let hasMake = false;
              let orientation = -1;
              for (let index = 0; index < entryCount; index++) {
                const entryOffset = ifdOffset + SEGMENT_LENGTH_SIZE + index * IFD_ENTRY_SIZE;
                const tag = view.getUint16(entryOffset, true);
                if (tag === MAKE_TAG) {
                  hasMake = bytesOf(MAKE_VALUE)
                    .every((byte, byteIndex) => bytes[entryOffset + IFD_ENTRY_VALUE_OFFSET + byteIndex] === byte);
                }
                if (tag === ORIENTATION_TAG) {
                  orientation = view.getUint16(entryOffset + IFD_ENTRY_VALUE_OFFSET, true);
                }
              }
              return { hasMake, orientation };
            }
            offset += SEGMENT_LENGTH_SIZE + segmentLength;
          }
          return { hasMake: false, orientation: -1 };
        }

        function isConversionSettings(value: unknown): value is ConversionSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['convertImagesToJpegMode'] === 'string'
            && typeof (value as Record<string, unknown>)['jpegQuality'] === 'number'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        function findSettings(): ConversionSettings | null {
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
            if (isConversionSettings(record['settings'])) {
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

        const EMPTY: MetadataRoundTripResult = {
          makeSurvived: false,
          orientation: -1,
          savedPath: '',
          settingsFound: false,
          sourceHadMake: false,
          sourceOrientation: -1
        };

        const foundSettings = findSettings();
        if (!foundSettings) {
          return EMPTY;
        }
        // A narrowed `let`/`const` does not stay narrowed inside a function declaration below it.
        const settings: ConversionSettings = foundSettings;

        /*
         * The desktop suite shares one Obsidian and one temporary vault, so a test that leaves the
         * plugin converting every image to JPEG changes what every later test saves. Restore what was
         * there before finishing, whatever happens in between.
         */
        const previousSettings = {
          attachmentFolderPath: settings.attachmentFolderPath,
          convertImagesToJpegMode: settings.convertImagesToJpegMode,
          shouldPreserveImageMetadata: settings.shouldPreserveImageMetadata
        };

        function restoreSettings(): void {
          settings.attachmentFolderPath = previousSettings.attachmentFolderPath;
          settings.convertImagesToJpegMode = previousSettings.convertImagesToJpegMode;
          settings.shouldPreserveImageMetadata = previousSettings.shouldPreserveImageMetadata;
        }

        settings.convertImagesToJpegMode = 'All images';
        settings.attachmentFolderPath = './';
        settings.shouldPreserveImageMetadata = shouldPreserve;

        try {
          const sourceBuffer = createJpegWithExif();
          const source = readExif(new Uint8Array(sourceBuffer));

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const note = await app.vault.create(`exif-note-${stamp}.md`, '');
          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          await sleep(500);

          const viewUnknown: unknown = leaf.view;
          const view = viewUnknown as MarkdownViewLike;
          const clipboardManager = view.editMode?.clipboardManager;
          if (!clipboardManager) {
            return { ...EMPTY, settingsFound: true };
          }

          const baseName = `exif-source-${stamp}`;
          // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
          const os = require('node:os') as OsModuleLike;
          // eslint-disable-next-line @typescript-eslint/no-require-imports -- Electron renderer require.
          const nodePath = require('node:path') as PathModuleLike;
          const temporaryFilePath = nodePath.join(os.tmpdir(), `${baseName}.jpg`);
          const adapterUnknown: unknown = app.vault.adapter;
          const fsPromises = (adapterUnknown as AdapterWithFsPromises).fsPromises;
          await fsPromises.writeFile(temporaryFilePath, new Uint8Array(sourceBuffer));

          // The attachment is renamed on save (a clipboard insert counts as pasted), so the saved file
          // Cannot be found by its source name. Watch for a JPEG that was not there before instead.
          const jpegPathsBefore = new Set(app.vault.getFiles().filter((file) => file.extension === 'jpg').map((file) => file.path));

          await clipboardManager.insertFiles([{
            data: Promise.resolve(sourceBuffer),
            extension: 'jpg',
            filepath: temporaryFilePath,
            name: `${baseName}.jpg`
          }]);

          // The save runs through OCAL's saveAttachment patch; poll until the converted JPEG lands.
          let savedPath = '';
          const deadline = Date.now() + 15_000;
          while (Date.now() < deadline) {
            const candidate = app.vault.getFiles().find((file) => file.extension === 'jpg' && !jpegPathsBefore.has(file.path));
            if (candidate) {
              savedPath = candidate.path;
              break;
            }
            await sleep(300);
          }

          await fsPromises.unlink(temporaryFilePath).catch(() => {
            // Best-effort temp cleanup.
          });
          leaf.detach();

          /*
           * The desktop suite shares one temporary vault, and a converted attachment left behind here
           * is an unused attachment as far as the collect / delete-unused tests are concerned — they
           * enumerate the vault and assert on exactly which files survive. Take the note and its
           * attachment back out.
           */
          async function cleanUpVault(): Promise<void> {
            for (const path of [savedPath, note.path]) {
              const file = path ? app.vault.getFileByPath(path) : null;
              if (file) {
                await app.fileManager.trashFile(file);
              }
            }
          }

          if (!savedPath) {
            await cleanUpVault();
            return { ...EMPTY, settingsFound: true, sourceHadMake: source.hasMake, sourceOrientation: source.orientation };
          }

          const savedFile = app.vault.getFileByPath(savedPath);
          if (!savedFile) {
            await cleanUpVault();
            return { ...EMPTY, settingsFound: true, sourceHadMake: source.hasMake, sourceOrientation: source.orientation };
          }
          const saved = readExif(new Uint8Array(await app.vault.readBinary(savedFile)));
          await cleanUpVault();

          return {
            makeSurvived: saved.hasMake,
            orientation: saved.orientation,
            savedPath,
            settingsFound: true,
            sourceHadMake: source.hasMake,
            sourceOrientation: source.orientation
          };
        } finally {
          restoreSettings();
        }
      },
      input: { shouldPreserveImageMetadata },
      vaultPath: getTemporaryVault().path
    });
  }

  it('carries the EXIF block across the conversion when the setting is on, upright', async () => {
    const result = await roundTrip(true);

    expect(result.settingsFound).toBe(true);
    // The fixture is only worth anything if it really carried the tags in the first place.
    expect(result.sourceHadMake).toBe(true);
    expect(result.sourceOrientation).toBe(3);

    expect(result.savedPath).not.toBe('');
    expect(result.makeSurvived).toBe(true);
    // Reset, because the canvas decode has already applied the rotation to the pixels.
    expect(result.orientation).toBe(1);
  }, 120_000);

  it('drops the EXIF block when the setting is off, which is what the conversion has always done', async () => {
    const result = await roundTrip(false);

    expect(result.settingsFound).toBe(true);
    expect(result.sourceHadMake).toBe(true);
    expect(result.savedPath).not.toBe('');
    expect(result.makeSurvived).toBe(false);
    expect(result.orientation).toBe(-1);
  }, 120_000);
});
