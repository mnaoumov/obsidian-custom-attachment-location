import type { Vault } from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { AttachmentSaver } from '../attachment-saver.ts';

interface VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams {
  readonly attachmentSaver: AttachmentSaver;
  readonly vault: Vault;
}

export class VaultGetAvailablePathForAttachmentsPatchComponent extends MonkeyAroundComponent {
  private readonly attachmentSaver: AttachmentSaver;
  private readonly vault: Vault;

  public constructor(params: VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams) {
    super();
    this.vault = params.vault;
    this.attachmentSaver = params.attachmentSaver;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'getAvailablePathForAttachments',
      obj: this.vault,
      patchHandler: ({
        fallback
      }) => {
        return fallback();
      },
      postPatchHandler: ({
        patchedMethod
      }) => {
        return Object.assign(patchedMethod, {
          extended: this.attachmentSaver.getAvailablePathForAttachments.bind(this.attachmentSaver)
        });
      }
    });
  }
}
