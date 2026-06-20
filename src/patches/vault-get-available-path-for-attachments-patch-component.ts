import type {
  TFile,
  Vault
} from 'obsidian';
import type { GetAvailablePathForAttachmentsFnExtended } from 'obsidian-dev-utils/obsidian/attachment-path';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';

type GetAvailablePathForAttachmentsFn = Vault['getAvailablePathForAttachments'];

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
    const vault = this.vault;
    this.registerPatch(this.vault, {
      getAvailablePathForAttachments: (originalFn: GetAvailablePathForAttachmentsFn): GetAvailablePathForAttachmentsFnExtended => {
        return Object.assign(originalFnCopy, {
          extended: this.customAttachmentLocationComponent.getAvailablePathForAttachments.bind(this.customAttachmentLocationComponent)
        });

        function originalFnCopy(filename: string, extension: string, file: null | TFile): Promise<string> {
          return originalFn.call(vault, filename, extension, file);
        }
      }
    });
  }
}
