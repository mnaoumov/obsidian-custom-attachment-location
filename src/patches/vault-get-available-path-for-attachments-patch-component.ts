import type { Vault } from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';

interface VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams {
  readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  readonly vault: Vault;
}

export class VaultGetAvailablePathForAttachmentsPatchComponent extends MonkeyAroundComponent {
  private readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  private readonly vault: Vault;

  public constructor(params: VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams) {
    super();
    this.vault = params.vault;
    this.customAttachmentLocationComponent = params.customAttachmentLocationComponent;
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
          extended: this.customAttachmentLocationComponent.getAvailablePathForAttachments.bind(this.customAttachmentLocationComponent)
        });
      }
    });
  }
}
