import type { Vault } from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';

interface VaultGetConfigPatchComponentConstructorParams {
  readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  readonly vault: Vault;
}

export class VaultGetConfigPatchComponent extends MonkeyAroundComponent {
  private readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  private readonly vault: Vault;

  public constructor(params: VaultGetConfigPatchComponentConstructorParams) {
    super();
    this.vault = params.vault;
    this.customAttachmentLocationComponent = params.customAttachmentLocationComponent;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'getConfig',
      obj: this.vault,
      patchHandler: ({
        fallback,
        originalArgs: [name]
      }) => {
        if (name !== 'attachmentFolderPath' || this.customAttachmentLocationComponent.currentAttachmentFolderPath === null) {
          return fallback();
        }

        return this.customAttachmentLocationComponent.currentAttachmentFolderPath;
      }
    });
  }
}
