import type { ClipboardManager } from '@obsidian-typings/obsidian-public-latest';

import { getPrototypeOf } from 'obsidian-dev-utils/object-utils';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { ArrayBufferMap } from '../array-buffer-map.ts';

interface ClipboardManagerInsertFilesPatchComponentConstructorParams {
  readonly arrayBufferMap: ArrayBufferMap;
  readonly clipboardManager: ClipboardManager;
}

export class ClipboardManagerInsertFilesPatchComponent extends MonkeyAroundComponent {
  private readonly arrayBufferMap: ArrayBufferMap;
  private readonly clipboardManager: ClipboardManager;

  public constructor(params: ClipboardManagerInsertFilesPatchComponentConstructorParams) {
    super();
    this.arrayBufferMap = params.arrayBufferMap;
    this.clipboardManager = params.clipboardManager;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'insertFiles',
      obj: getPrototypeOf(this.clipboardManager),
      patchHandler: async ({
        fallback,
        originalArgs: [importedAttachments]
      }) => {
        for (const importedAttachment of importedAttachments) {
          const arrayBuffer = await importedAttachment.data;
          await this.arrayBufferMap.trySetByPath(arrayBuffer, importedAttachment.filepath);
        }
        return fallback();
      }
    });
  }
}
