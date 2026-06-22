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

  public constructor(params: ArrayBufferMapConstructorParams) {
    this.app = params.app;
  }

  public getFileStats(arrayBuffer: ArrayBuffer): FileStats | undefined {
    return this.fileStatsMap.get(arrayBuffer);
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
