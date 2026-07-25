const IMAGE_MIME_TYPE_BY_EXTENSION: Record<string, string> = {
  avif: 'image/avif',
  bmp: 'image/bmp',
  gif: 'image/gif',
  jpeg: 'image/jpeg',
  jpg: 'image/jpeg',
  png: 'image/png',
  svg: 'image/svg+xml',
  webp: 'image/webp'
};

/**
 * Resolves the image MIME type for a file extension.
 *
 * @param extension - The file extension (without a leading dot; case-insensitive).
 * @returns The MIME type, or `null` when the extension is not a known image extension.
 */
export function getImageMimeType(extension: string): null | string {
  return IMAGE_MIME_TYPE_BY_EXTENSION[extension.toLowerCase()] ?? null;
}

/**
 * Checks whether a file extension denotes a known image type.
 *
 * @param extension - The file extension (without a leading dot; case-insensitive).
 * @returns `true` when the extension is a known image extension.
 */
export function isImageExtension(extension: string): boolean {
  return getImageMimeType(extension) !== null;
}
