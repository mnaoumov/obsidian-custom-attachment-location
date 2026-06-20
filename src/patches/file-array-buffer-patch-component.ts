import { webUtils } from 'electron';
import {
  App,
  FileSystemAdapter
} from 'obsidian';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';

interface FileArrayBufferPatchComponentConstructorParams {
  readonly app: App;
  readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  readonly file: File;
}

export class FileArrayBufferPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  private readonly file: File;

  public constructor(params: FileArrayBufferPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.customAttachmentLocationComponent = params.customAttachmentLocationComponent;
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
          if (await this.customAttachmentLocationComponent.setFileStat(arrayBuffer, path)) {
            return arrayBuffer;
          }
        }

        this.customAttachmentLocationComponent.arrayBufferFileStatMap.set(arrayBuffer, {
          ctime: 0,
          mtime: this.file.lastModified,
          size: this.file.size
        });
        return arrayBuffer;
      }
    });
  }
}
