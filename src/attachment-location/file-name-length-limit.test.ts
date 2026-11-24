import {
  describe,
  expect,
  it
} from 'vitest';

import {
  fitFileBaseName,
  MAX_FILE_NAME_LENGTH,
  MAX_WINDOWS_PATH_LENGTH
} from './file-name-length-limit.ts';

// The kind of vault issue #108 was reported from: Obsidian's sandbox, under the roaming application data folder.
const SANDBOX_VAULT_PATH = String.raw`C:\Users\user\AppData\Roaming\obsidian\Obsidian Sandbox`;
const SUFFIX_ROOM = ' 9999'.length;

describe('fitFileBaseName', () => {
  it('should keep a name that fits', () => {
    expect(fitFileBaseName({
      absoluteVaultPath: SANDBOX_VAULT_PATH,
      duplicateNameSeparator: ' ',
      fileBaseName: 'Pasted image 20261123',
      fileExtension: 'png',
      folderPath: 'assets',
      isWindows: true
    })).toEqual({ fileBaseName: 'Pasted image 20261123', isShortened: false });
  });

  it('should keep the whole name within the file name limit on Windows', () => {
    const result = fitFileBaseName({
      absoluteVaultPath: 'C:\\v',
      duplicateNameSeparator: ' ',
      fileBaseName: 'a'.repeat(300),
      fileExtension: 'png',
      folderPath: '',
      isWindows: true
    });
    expect(result.isShortened).toBe(true);
    expect(`${result.fileBaseName}.png`.length + SUFFIX_ROOM).toBeLessThanOrEqual(MAX_FILE_NAME_LENGTH);
  });

  it('should keep the absolute path within MAX_PATH on Windows, as a 200-character heading in the sandbox vault exceeds it', () => {
    const result = fitFileBaseName({
      absoluteVaultPath: SANDBOX_VAULT_PATH,
      duplicateNameSeparator: ' ',
      fileBaseName: 'b'.repeat(196),
      fileExtension: 'png',
      folderPath: 'Notes/assets',
      isWindows: true
    });
    expect(result.isShortened).toBe(true);
    const absolutePath = `${SANDBOX_VAULT_PATH}\\Notes\\assets\\${result.fileBaseName}.png`;
    expect(absolutePath.length + SUFFIX_ROOM).toBe(MAX_WINDOWS_PATH_LENGTH);
  });

  it('should treat a trailing separator on the vault path and a root folder of / as nothing', () => {
    const withSeparator = fitFileBaseName({
      absoluteVaultPath: 'C:\\v\\',
      duplicateNameSeparator: ' ',
      fileBaseName: 'c'.repeat(300),
      fileExtension: 'png',
      folderPath: '/',
      isWindows: true
    });
    const without = fitFileBaseName({
      absoluteVaultPath: 'C:\\v',
      duplicateNameSeparator: ' ',
      fileBaseName: 'c'.repeat(300),
      fileExtension: 'png',
      folderPath: '',
      isWindows: true
    });
    expect(withSeparator).toEqual(without);
  });

  it('should count UTF-8 bytes off Windows', () => {
    const result = fitFileBaseName({
      absoluteVaultPath: '/home/user/vault',
      duplicateNameSeparator: ' ',
      fileBaseName: 'ж'.repeat(200),
      fileExtension: 'png',
      folderPath: 'assets',
      isWindows: false
    });
    expect(result.isShortened).toBe(true);
    expect(new TextEncoder().encode(`${result.fileBaseName}.png`).byteLength + SUFFIX_ROOM).toBeLessThanOrEqual(MAX_FILE_NAME_LENGTH);
    expect(result.fileBaseName).toBe('ж'.repeat(123));
  });

  it('should bound the name without a vault path, as on mobile', () => {
    const result = fitFileBaseName({
      absoluteVaultPath: null,
      duplicateNameSeparator: ' ',
      fileBaseName: 'd'.repeat(300),
      fileExtension: '',
      folderPath: 'assets',
      isWindows: false
    });
    expect(result.fileBaseName).toHaveLength(MAX_FILE_NAME_LENGTH - SUFFIX_ROOM);
  });

  it('should never split a surrogate pair', () => {
    const result = fitFileBaseName({
      absoluteVaultPath: 'C:\\v',
      duplicateNameSeparator: ' ',
      fileBaseName: '😀'.repeat(200),
      fileExtension: 'png',
      folderPath: '',
      isWindows: true
    });
    expect(result.isShortened).toBe(true);
    expect(result.fileBaseName).toBe('😀'.repeat(result.fileBaseName.length / 2));
  });

  it('should drop the dots and spaces a cut leaves at the end', () => {
    const result = fitFileBaseName({
      absoluteVaultPath: null,
      duplicateNameSeparator: ' ',
      fileBaseName: `${'e'.repeat(243)} . ${'f'.repeat(100)}`,
      fileExtension: 'png',
      folderPath: '',
      isWindows: false
    });
    expect(result).toEqual({ fileBaseName: 'e'.repeat(243), isShortened: true });
  });

  it('should leave the name alone when the folder leaves no room for one', () => {
    const fileBaseName = 'g'.repeat(50);
    expect(fitFileBaseName({
      absoluteVaultPath: 'C:\\v',
      duplicateNameSeparator: ' ',
      fileBaseName,
      fileExtension: 'png',
      folderPath: 'h'.repeat(260),
      isWindows: true
    })).toEqual({ fileBaseName, isShortened: false });
  });
});
