import type {
  App,
  FileStats
} from 'obsidian';

import {
  CapacitorAdapter,
  FileSystemAdapter
} from 'obsidian';

interface ArrayBufferMapConstructorParams {
  readonly app: App;
}

export class ArrayBufferMap {
  private readonly app: App;
  private readonly fileStatsMap = new WeakMap<ArrayBuffer, FileStats>();
  private readonly pastedImageArrayBuffers = new WeakSet<ArrayBuffer>();

  public constructor(params: ArrayBufferMapConstructorParams) {
    this.app = params.app;
  }

  public getFileStats(arrayBuffer: ArrayBuffer): FileStats | undefined {
    return this.fileStatsMap.get(arrayBuffer);
  }

  /**
   * Reports whether the given attachment content was pasted/inserted as an image via the clipboard
   * or the editor insert-files flow.
   *
   * This is an explicit, filename-independent signal: the clipboard `insertFiles` interception marks
   * the exact `ArrayBuffer` that later reaches {@link AttachmentSaver}, so genuine clipboard image
   * pastes are detected even when Obsidian does not name them `Pasted image <timestamp>` (e.g. a
   * Windows 11 Win+Shift+S screenshot that is backed by a real temp file).
   *
   * @param arrayBuffer - The attachment content.
   * @returns `true` when the content was recorded as a pasted image.
   */
  public isPastedImage(arrayBuffer: ArrayBuffer): boolean {
    return this.pastedImageArrayBuffers.has(arrayBuffer);
  }

  /**
   * Records that the given attachment content was pasted/inserted as an image.
   *
   * @param arrayBuffer - The attachment content.
   */
  public markAsPastedImage(arrayBuffer: ArrayBuffer): void {
    this.pastedImageArrayBuffers.add(arrayBuffer);
  }

  public setFileStats(arrayBuffer: ArrayBuffer, fileStats: FileStats): void {
    this.fileStatsMap.set(arrayBuffer, fileStats);
  }

  public async trySetByPath(arrayBuffer: ArrayBuffer, filePath: string): Promise<boolean> {
    if (!filePath) {
      return false;
    }

    if (this.app.vault.adapter instanceof FileSystemAdapter) {
      const stats = await this.app.vault.adapter.fsPromises.stat(filePath);
      this.fileStatsMap.set(arrayBuffer, {
        ctime: stats.ctimeMs,
        mtime: stats.mtimeMs,
        size: stats.size
      });
      return true;
    }

    if (this.app.vault.adapter instanceof CapacitorAdapter) {
      const stats = await this.app.vault.adapter.fs.stat(filePath);
      this.fileStatsMap.set(arrayBuffer, {
        ctime: stats.ctime ?? 0,
        mtime: stats.mtime ?? 0,
        size: arrayBuffer.byteLength
      });
      return true;
    }

    return false;
  }
}
