import type { ClipboardManager } from '@obsidian-typings/obsidian-public-latest';

import { getPrototypeOf } from 'obsidian-dev-utils/object-utils';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { ArrayBufferMap } from '../array-buffer-map.ts';

import { isImageExtension } from '../image-mime-types.ts';

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
      $object: getPrototypeOf(this.clipboardManager),
      methodName: 'insertFiles',
      patchHandler: async ({
        fallback,
        originalArguments: [importedAttachments]
      }) => {
        for (const importedAttachment of importedAttachments) {
          const arrayBuffer = await importedAttachment.data;
          // `insertFiles` is the clipboard-paste / editor insert sink. Image attachments are flagged
          // By exact ArrayBuffer identity so `Attachment rename mode: Only pasted images` detects them
          // Without depending on Obsidian's `Pasted image <timestamp>` naming, which is absent for a
          // Windows 11 Win+Shift+S screenshot backed by a real temp file. See issue #31.
          if (isImageExtension(importedAttachment.extension)) {
            this.arrayBufferMap.markAsPastedImage(arrayBuffer);
          }
          await this.arrayBufferMap.trySetByPath(arrayBuffer, importedAttachment.filepath);
        }
        return fallback();
      }
    });
  }
}
