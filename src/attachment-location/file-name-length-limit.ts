/**
 * The longest file name every desktop and mobile file system Obsidian runs on accepts: NTFS counts it in UTF-16 code
 * units, while the Linux, macOS, Android and iOS file systems count it in UTF-8 bytes. A longer name fails the write, and core
 * swallows that failure, so a paste just does nothing (issue #108).
 */
export const MAX_FILE_NAME_LENGTH = 255;

/**
 * The longest absolute path Windows accepts without the long-path prefix: `MAX_PATH` (260) less its terminating null.
 * Node writes past it, because libuv adds the prefix, but Chromium's resource loader and Electron's trash do not, so
 * a longer path saves a file Obsidian then shows as a broken image and cannot delete (issue #108).
 */
export const MAX_WINDOWS_PATH_LENGTH = 259;

/**
 * Room kept free for the duplicate-name suffix a taken name gets (the separator plus a number), so a name fitted here
 * still fits once that suffix is appended.
 */
const DUPLICATE_SUFFIX_DIGIT_COUNT = 4;

/**
 * A name shorter than this is not worth producing: the folder alone leaves no room for a meaningful name, so the name
 * is left as it is and the write reports the folder.
 */
const MIN_FITTED_BASE_NAME_LENGTH = 1;

interface FitFileBaseNameParams {
  /**
   * The absolute path of the vault folder, or `null` where the vault has none (mobile).
   */
  readonly absoluteVaultPath: null | string;
  /**
   * The separator the duplicate-name suffix uses.
   */
  readonly duplicateNameSeparator: string;
  /**
   * The file's base name, without its extension.
   */
  readonly fileBaseName: string;
  /**
   * The file's extension, without the dot; empty for none.
   */
  readonly fileExtension: string;
  /**
   * The vault-relative folder the file goes into; empty or `/` for the vault root.
   */
  readonly folderPath: string;
  /**
   * Whether the file system is Windows', which counts names in UTF-16 code units and bounds the whole path.
   */
  readonly isWindows: boolean;
}

interface FitFileBaseNameResult {
  readonly fileBaseName: string;
  readonly isShortened: boolean;
}

/**
 * Shortens a file's base name so the file can be written, read back and deleted on the current file system.
 *
 * The extension and the room for a duplicate-name suffix are kept; the base name is cut at a code point boundary, and
 * the dots and spaces the cut leaves at its end are dropped, since Windows does not allow a name to end on either.
 *
 * @param params - The name, its folder and the file system.
 * @returns The base name to use, and whether it was shortened.
 */
export function fitFileBaseName(params: FitFileBaseNameParams): FitFileBaseNameResult {
  const measure = params.isWindows ? measureUtf16 : measureUtf8;
  const extensionLength = params.fileExtension ? measure(`.${params.fileExtension}`) : 0;
  const suffixLength = measure(params.duplicateNameSeparator) + DUPLICATE_SUFFIX_DIGIT_COUNT;

  let budget = MAX_FILE_NAME_LENGTH - extensionLength - suffixLength;

  if (params.isWindows && params.absoluteVaultPath !== null) {
    const folderPath = params.folderPath === '/' ? '' : params.folderPath;
    const folderPrefixLength = params.absoluteVaultPath.replace(/[\\/]+$/, '').length + 1 + (folderPath ? folderPath.length + 1 : 0);
    budget = Math.min(budget, MAX_WINDOWS_PATH_LENGTH - folderPrefixLength - extensionLength - suffixLength);
  }

  if (measure(params.fileBaseName) <= budget || budget < MIN_FITTED_BASE_NAME_LENGTH) {
    return { fileBaseName: params.fileBaseName, isShortened: false };
  }

  let fileBaseName = '';
  let length = 0;
  for (const codePoint of params.fileBaseName) {
    const codePointLength = measure(codePoint);
    if (length + codePointLength > budget) {
      break;
    }
    fileBaseName += codePoint;
    length += codePointLength;
  }

  fileBaseName = fileBaseName.replace(/[. ]+$/, '');
  // A cut that leaves only dots and spaces leaves nothing worth naming, so the name stays as it was.
  return fileBaseName
    ? { fileBaseName, isShortened: true }
    : { fileBaseName: params.fileBaseName, isShortened: false };
}

function measureUtf16(value: string): number {
  return value.length;
}

function measureUtf8(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
