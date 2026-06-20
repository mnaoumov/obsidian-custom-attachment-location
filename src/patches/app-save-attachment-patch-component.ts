import type { App } from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { CustomAttachmentLocationComponent } from '../custom-attachment-location-component.ts';

interface AppSaveAttachmentPatchComponentConstructorParams {
  readonly app: App;
  readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
}

export class AppSaveAttachmentPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;

  public constructor(params: AppSaveAttachmentPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.customAttachmentLocationComponent = params.customAttachmentLocationComponent;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'saveAttachment',
      obj: this.app,
      patchHandler: ({
        originalArgs: [name, extension, data]
      }) => {
        return this.customAttachmentLocationComponent.saveAttachment(name, extension, data);
      }
    });
  }
}
