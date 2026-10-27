import type { FileStats } from 'obsidian';

import {
  describe,
  expect,
  it
} from 'vitest';

import type { IsPastedImageParams } from './pasted-image-classifier.ts';

import { PluginSettings } from '../settings/plugin-settings.ts';
import { InsertGesture } from './insert-gesture-tracker-component.ts';
import {
  FRESH_SCREENSHOT_FILE_THRESHOLD_IN_MILLISECONDS,
  isPastedImage,
  isScreenshotFilePath
} from './pasted-image-classifier.ts';

const NOW = 1_800_000_000_000;
const OLD_FILE_STATS: FileStats = { ctime: 0, mtime: NOW - 3_600_000, size: 4 };
const FRESH_FILE_STATS: FileStats = { ctime: 0, mtime: NOW - 5000, size: 4 };

function isClassifiedAsPasted(overrides: Partial<IsPastedImageParams>): boolean {
  return isPastedImage({
    extension: 'png',
    filePath: 'C:/Users/me/Pictures/photo.png',
    fileStats: OLD_FILE_STATS,
    gesture: InsertGesture.Paste,
    now: NOW,
    screenshotFilePaths: [],
    shouldKeepNamesOfPastedNonScreenshotFiles: true,
    ...overrides
  });
}

describe('isPastedImage', () => {
  it('should never treat a non-image as pasted', () => {
    expect(isClassifiedAsPasted({ extension: 'pdf', filePath: '' })).toBe(false);
  });

  it('should treat image data with no file behind it as pasted, whatever the gesture', () => {
    expect(isClassifiedAsPasted({ filePath: '' })).toBe(true);
    expect(isClassifiedAsPasted({ filePath: '', gesture: InsertGesture.Drop })).toBe(true);
    expect(isClassifiedAsPasted({ filePath: '', gesture: null })).toBe(true);
  });

  it('should never treat a dropped file as pasted, even a fresh screenshot', () => {
    expect(isClassifiedAsPasted({
      filePath: 'C:/Temp/PixPin_2026-10-16_22-00-00.png',
      fileStats: FRESH_FILE_STATS,
      gesture: InsertGesture.Drop,
      screenshotFilePaths: ['/PixPin_/']
    })).toBe(false);
  });

  it('should treat a pasted file on a screenshot path as pasted, however old it is', () => {
    expect(isClassifiedAsPasted({ filePath: 'C:/Temp/PixPin_2026-10-16_22-00-00.png', screenshotFilePaths: ['/PixPin_/'] })).toBe(true);
  });

  it('should treat a pasted file written moments ago as pasted', () => {
    expect(isClassifiedAsPasted({ fileStats: FRESH_FILE_STATS })).toBe(true);
  });

  it('should keep an old pasted file that is on no screenshot path', () => {
    expect(isClassifiedAsPasted({})).toBe(false);
    expect(isClassifiedAsPasted({ fileStats: { ctime: 0, mtime: NOW - FRESH_SCREENSHOT_FILE_THRESHOLD_IN_MILLISECONDS, size: 4 } })).toBe(false);
  });

  it('should keep a pasted file whose stats could not be read', () => {
    expect(isClassifiedAsPasted({ fileStats: undefined })).toBe(false);
  });

  it('should treat every pasted file as pasted while the names of non-screenshot files are not kept', () => {
    expect(isClassifiedAsPasted({ shouldKeepNamesOfPastedNonScreenshotFiles: false })).toBe(true);
    expect(isClassifiedAsPasted({ fileStats: undefined, shouldKeepNamesOfPastedNonScreenshotFiles: false })).toBe(true);
    expect(isClassifiedAsPasted({ gesture: null, shouldKeepNamesOfPastedNonScreenshotFiles: false })).toBe(true);
  });

  it('should keep a dropped file even while the names of non-screenshot files are not kept', () => {
    expect(isClassifiedAsPasted({ gesture: InsertGesture.Drop, shouldKeepNamesOfPastedNonScreenshotFiles: false })).toBe(false);
  });

  it('should never treat a non-image as pasted while the names of non-screenshot files are not kept', () => {
    expect(isClassifiedAsPasted({ extension: 'pdf', shouldKeepNamesOfPastedNonScreenshotFiles: false })).toBe(false);
  });

  it('should classify a call outside any gesture like a paste', () => {
    expect(isClassifiedAsPasted({ fileStats: FRESH_FILE_STATS, gesture: null })).toBe(true);
    expect(isClassifiedAsPasted({ gesture: null })).toBe(false);
  });
});

describe('isScreenshotFilePath', () => {
  it('should test a regular expression entry against the full path, ignoring case', () => {
    expect(isScreenshotFilePath(String.raw`C:\Temp\pixpin_1.png`, [String.raw`/[\\/]PixPin_[^\\/]*$/`])).toBe(true);
    expect(isScreenshotFilePath(String.raw`C:\PixPin_1\photo.png`, [String.raw`/[\\/]PixPin_[^\\/]*$/`])).toBe(false);
  });

  it('should match a file inside a folder entry, whatever the separators and case', () => {
    expect(isScreenshotFilePath(String.raw`C:\Users\Me\Shots\a.png`, ['c:/users/me/shots'])).toBe(true);
    expect(isScreenshotFilePath('/Users/me/Shots/a.png', ['/Users/me/Shots'])).toBe(true);
    expect(isScreenshotFilePath(String.raw`C:\Users\Me\Shots\a.png`, ['C:\\Users\\Me\\Shots\\'])).toBe(true);
  });

  it('should not match a sibling folder that merely shares the prefix', () => {
    expect(isScreenshotFilePath('C:/Users/me/Shots2/a.png', ['C:/Users/me/Shots'])).toBe(false);
  });

  it('should ignore a blank entry and an invalid regular expression', () => {
    expect(isScreenshotFilePath('C:/a.png', ['', ' '.repeat(3), '/(/'])).toBe(false);
  });

  it('should match what the default entries are meant to match', () => {
    const defaults = new PluginSettings().screenshotFilePaths;
    expect(isScreenshotFilePath(String.raw`C:\Users\me\AppData\Roaming\PixPin\Temp\PixPin_2026-10-16_22-00-00.png`, defaults)).toBe(true);
    expect(isScreenshotFilePath('/Users/me/Desktop/Snipaste_2026-10-16_22-00-00.png', defaults)).toBe(true);
    expect(isScreenshotFilePath('/Users/me/Desktop/Screenshot 2026-10-16 at 22.00.00.png', defaults)).toBe(true);
    expect(
      isScreenshotFilePath(
        String.raw`C:\Users\me\AppData\Local\Packages\MicrosoftWindows.Client.CBS_abc\TempState\ScreenClip\{GUID}.png`,
        defaults
      )
    ).toBe(true);
    expect(isScreenshotFilePath(String.raw`C:\Users\me\AppData\Local\Temp\clip.png`, defaults)).toBe(true);
    expect(isScreenshotFilePath('/tmp/clip.png', defaults)).toBe(true);
    expect(isScreenshotFilePath('/var/folders/x/T/clip.png', defaults)).toBe(true);
    expect(isScreenshotFilePath(String.raw`C:\Users\me\Pictures\holiday.png`, defaults)).toBe(false);
  });
});
