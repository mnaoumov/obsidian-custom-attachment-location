import { webUtils } from 'electron';
import {
  App,
  FileSystemAdapter
} from 'obsidian';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { ArrayBufferMap } from '../array-buffer-map.ts';

interface FileArrayBufferPatchComponentConstructorParams {
  readonly app: App;
  readonly arrayBufferMap: ArrayBufferMap;
  readonly file: File;
}

export class FileArrayBufferPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly arrayBufferMap: ArrayBufferMap;
  private readonly file: File;

  public constructor(params: FileArrayBufferPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.arrayBufferMap = params.arrayBufferMap;
    this.file = params.file;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'arrayBuffer',
      obj: this.file,
      patchHandler: async ({
        fallback
      }) => {
        const arrayBuffer = await fallback();
        if (this.app.vault.adapter instanceof FileSystemAdapter) {
          const path = webUtils.getPathForFile(this.file);
          if (await this.arrayBufferMap.trySetByPath(arrayBuffer, path)) {
            return arrayBuffer;
          }
        }

        this.arrayBufferMap.setFileStats(arrayBuffer, {
          ctime: 0,
          mtime: this.file.lastModified,
          size: this.file.size
        });
        return arrayBuffer;
      }
    });
  }
}
