import type { ClipboardManager } from '@obsidian-typings/obsidian-public-latest';

import { getPrototypeOf } from 'obsidian-dev-utils/object-utils';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';

interface ClipboardManagerInsertFilesPatchComponentConstructorParams {
  readonly clipboardManager: ClipboardManager;
  readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
}

export class ClipboardManagerInsertFilesPatchComponent extends MonkeyAroundComponent {
  private readonly clipboardManager: ClipboardManager;
  private readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;

  public constructor(params: ClipboardManagerInsertFilesPatchComponentConstructorParams) {
    super();
    this.clipboardManager = params.clipboardManager;
    this.customAttachmentLocationComponent = params.customAttachmentLocationComponent;
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
          await this.customAttachmentLocationComponent.setFileStat(arrayBuffer, importedAttachment.filepath);
        }
        return fallback();
      }
    });
  }
}
