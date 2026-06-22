import type { Vault } from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';

interface VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams {
  readonly attachmentPathManager: AttachmentPathManager;
  readonly vault: Vault;
}

export class VaultGetAvailablePathForAttachmentsPatchComponent extends MonkeyAroundComponent {
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly vault: Vault;

  public constructor(params: VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams) {
    super();
    this.vault = params.vault;
    this.attachmentPathManager = params.attachmentPathManager;
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
          extended: this.attachmentPathManager.getAvailablePathForAttachments.bind(this.attachmentPathManager)
        });
      }
    });
  }
}
