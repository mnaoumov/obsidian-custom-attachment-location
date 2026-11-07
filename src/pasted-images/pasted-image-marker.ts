import type { ImportedAttachment } from '@obsidian-typings/obsidian-public-latest';

import type { ArrayBufferMap } from '../attachment-saving/array-buffer-map.ts';

import { NewAttachmentOperation } from '../attachment-saving/new-attachment-operation.ts';
import { InsertGesture } from './insert-gesture-tracker-component.ts';
import { isPastedImage } from './pasted-image-classifier.ts';

interface PastedImageMarkerConstructorParams {
  readonly arrayBufferMap: ArrayBufferMap;
  readonly getScreenshotFilePaths: (this: void) => readonly string[];
  readonly getShouldKeepNamesOfPastedNonScreenshotFiles: (this: void) => boolean;
}

/**
 * Records, for the attachments Obsidian is about to save, the file stats, whether each one is a pasted image, and
 * which new-attachment operation brought it in (a pasted screenshot, a pasted file or a dropped file).
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
   * @param canBePastedImage - Whether an attachment may count as a pasted image at all. `App.importAttachments` passes
   * `false` for a drop, which it never classified, so a canvas or file-explorer drop keeps its name as it always did.
   */
  public async record(importedAttachments: readonly ImportedAttachment[], gesture: InsertGesture | null, canBePastedImage = true): Promise<void> {
    for (const importedAttachment of importedAttachments) {
      const arrayBuffer = await importedAttachment.data;
      if (!arrayBuffer) {
        continue;
      }

      // The clipboard-image fallback item carries no `filepath`: the clipboard held only image data.
      const filePath = importedAttachment.filepath ?? '';
      await this.arrayBufferMap.trySetByPath(arrayBuffer, filePath);
      if (
        canBePastedImage && isPastedImage({
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
        this.arrayBufferMap.setNewAttachmentOperation(arrayBuffer, NewAttachmentOperation.PastedImage);
      } else if (gesture !== null) {
        this.arrayBufferMap.setNewAttachmentOperation(
          arrayBuffer,
          gesture === InsertGesture.Drop ? NewAttachmentOperation.DroppedFile : NewAttachmentOperation.PastedFile
        );
      }
    }
  }
}
