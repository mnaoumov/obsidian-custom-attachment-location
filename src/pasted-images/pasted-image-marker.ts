import type { ImportedAttachment } from '@obsidian-typings/obsidian-public-latest';

import type { ArrayBufferMap } from '../attachment-saving/array-buffer-map.ts';
import type { InsertGesture } from './insert-gesture-tracker-component.ts';

import { isPastedImage } from './pasted-image-classifier.ts';

interface PastedImageMarkerConstructorParams {
  readonly arrayBufferMap: ArrayBufferMap;
  readonly getScreenshotFilePaths: (this: void) => readonly string[];
  readonly getShouldKeepNamesOfPastedNonScreenshotFiles: (this: void) => boolean;
}

/**
 * Records, for the attachments Obsidian is about to save, the file stats and whether each one is a pasted image.
 *
 * Both are keyed by the attachment's `ArrayBuffer`, which is the one value that reaches `AttachmentSaver` unchanged,
 * so `Only pasted images` does not depend on Obsidian's `Pasted image <timestamp>` naming (issue #31).
 */
export class PastedImageMarker {
  private readonly arrayBufferMap: ArrayBufferMap;
  private readonly getScreenshotFilePaths: (this: void) => readonly string[];
  private readonly getShouldKeepNamesOfPastedNonScreenshotFiles: (this: void) => boolean;

  public constructor(params: PastedImageMarkerConstructorParams) {
    this.arrayBufferMap = params.arrayBufferMap;
    this.getScreenshotFilePaths = params.getScreenshotFilePaths;
    this.getShouldKeepNamesOfPastedNonScreenshotFiles = params.getShouldKeepNamesOfPastedNonScreenshotFiles;
  }

  /**
   * Records the attachments.
   *
   * @param importedAttachments - The attachments, as Obsidian collected them from the clipboard or the drop.
   * @param gesture - The gesture that brought them in. The caller reads it before its first `await`, because the
   * tracker clears it once the DOM event has been dispatched.
   */
  public async record(importedAttachments: readonly ImportedAttachment[], gesture: InsertGesture | null): Promise<void> {
    for (const importedAttachment of importedAttachments) {
      const arrayBuffer = await importedAttachment.data;
      if (!arrayBuffer) {
        continue;
      }

      // The clipboard-image fallback item carries no `filepath`: the clipboard held only image data.
      const filePath = importedAttachment.filepath ?? '';
      await this.arrayBufferMap.trySetByPath(arrayBuffer, filePath);
      if (
        isPastedImage({
          extension: importedAttachment.extension,
          filePath,
          fileStats: this.arrayBufferMap.getFileStats(arrayBuffer),
          gesture,
          now: Date.now(),
          screenshotFilePaths: this.getScreenshotFilePaths(),
          shouldKeepNamesOfPastedNonScreenshotFiles: this.getShouldKeepNamesOfPastedNonScreenshotFiles()
        })
      ) {
        this.arrayBufferMap.markAsPastedImage(arrayBuffer);
      }
    }
  }
}
