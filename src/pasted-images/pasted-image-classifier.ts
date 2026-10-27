import type { FileStats } from 'obsidian';

import { isValidRegExp } from '@mnaoumov/typescript-lib/reg-exp';

import { isImageExtension } from '../attachment-saving/image-mime-types.ts';
import { InsertGesture } from './insert-gesture-tracker-component.ts';

/**
 * How recently a file must have been written to count as a screenshot taken for this paste.
 *
 * A screenshot tool that copies its capture as a file writes that file at capture time, so it is seconds old when
 * it is pasted. A real file the user copies in a file manager is almost always older.
 */
export const FRESH_SCREENSHOT_FILE_THRESHOLD_IN_MILLISECONDS = 60_000;

/**
 * The parameters for {@link isPastedImage}.
 */
export interface IsPastedImageParams {
  /**
   * The extension of the attachment, without a leading dot.
   */
  readonly extension: string;

  /**
   * The path of the file on disk, or an empty string when the clipboard held only image data.
   */
  readonly filePath: string;

  /**
   * The file's stats, when they could be read.
   */
  readonly fileStats: FileStats | undefined;

  /**
   * The gesture being dispatched, or `null` when there was none.
   */
  readonly gesture: InsertGesture | null;

  /**
   * The current time, in milliseconds since the epoch.
   */
  readonly now: number;

  /**
   * The `Screenshot file paths` setting entries.
   */
  readonly screenshotFilePaths: readonly string[];

  /**
   * The `Keep the names of pasted image files that are not screenshots` setting.
   */
  readonly shouldKeepNamesOfPastedNonScreenshotFiles: boolean;
}

/**
 * Decides whether an image that is being inserted is a screenshot, which is what `Only pasted images` renames.
 *
 * The cases are checked in this order:
 *
 * 1. **No file path:** the clipboard held only image data. Obsidian names it `Pasted image`, and it is the classic
 *    screenshot.
 * 2. **A drop:** the user dragged a file in. Its name is meant to be kept.
 * 3. **A paste with a path:** the clipboard held a file. Screenshot tools such as PixPin (with `Copy images as files`)
 *    and the Windows 11 Snipping Tool copy their capture this way, and so does a file manager copying a real file.
 *    By default it counts as pasted: capture tools that copy as a file are too many for any list to name, and a
 *    capture that keeps its own name is the regression issue #97 reported. Only when
 *    `shouldKeepNamesOfPastedNonScreenshotFiles` is on does it have to look like a screenshot: its path matches a
 *    `Screenshot file paths` entry, or the file was written less than
 *    {@link FRESH_SCREENSHOT_FILE_THRESHOLD_IN_MILLISECONDS} ago.
 *
 * @param params - The parameters.
 * @returns `true` when the image should be treated as pasted.
 */
export function isPastedImage(params: IsPastedImageParams): boolean {
  if (!isImageExtension(params.extension)) {
    return false;
  }

  if (!params.filePath) {
    return true;
  }

  const isDropped = params.gesture === InsertGesture.Drop;
  return !isDropped && (
    !params.shouldKeepNamesOfPastedNonScreenshotFiles
    || isScreenshotFilePath(params.filePath, params.screenshotFilePaths)
    || isFreshFile(params.fileStats, params.now)
  );
}

/**
 * Checks a file path against the `Screenshot file paths` setting.
 *
 * An entry wrapped in `/` is a regular expression, tested against the full path. Any other entry is a folder, and
 * the path matches when it is inside that folder. Both forms ignore case, and a folder entry treats `\` and `/` as
 * the same separator, because the paths come from the operating system rather than from the vault.
 *
 * @param filePath - The path of the file on disk.
 * @param screenshotFilePaths - The setting entries.
 * @returns `true` when an entry matches.
 */
export function isScreenshotFilePath(filePath: string, screenshotFilePaths: readonly string[]): boolean {
  const normalizedFilePath = normalizeSeparators(filePath).toLowerCase();
  return screenshotFilePaths.some((entry) => {
    // `//` would be an empty expression, which matches every path.
    if (entry.length > '//'.length && entry.startsWith('/') && entry.endsWith('/')) {
      const regExpSource = entry.slice(1, -1);
      // The settings validator refuses an invalid expression, but a hand-edited `data.json` can still carry one,
      // and a throw here would break the paste itself.
      return isValidRegExp(regExpSource) && new RegExp(regExpSource, 'i').test(filePath);
    }

    const folderPath = normalizeSeparators(entry.trim()).replace(/\/+$/, '').toLowerCase();
    return folderPath !== '' && normalizedFilePath.startsWith(`${folderPath}/`);
  });
}

function isFreshFile(fileStats: FileStats | undefined, now: number): boolean {
  return fileStats !== undefined && now - fileStats.mtime < FRESH_SCREENSHOT_FILE_THRESHOLD_IN_MILLISECONDS;
}

function normalizeSeparators(path: string): string {
  return path.replaceAll('\\', '/');
}
