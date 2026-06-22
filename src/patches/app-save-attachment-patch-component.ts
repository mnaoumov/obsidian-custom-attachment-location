import type { App } from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';

import type { AttachmentSaver } from '../attachment-saver.ts';

interface AppSaveAttachmentPatchComponentConstructorParams {
  readonly app: App;
  readonly attachmentSaver: AttachmentSaver;
}

export class AppSaveAttachmentPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly attachmentSaver: AttachmentSaver;

  public constructor(params: AppSaveAttachmentPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.attachmentSaver = params.attachmentSaver;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'saveAttachment',
      obj: this.app,
      patchHandler: ({
        originalArgs: [name, extension, data]
      }) => {
        return this.attachmentSaver.saveAttachment(name, extension, data);
      }
    });
  }
}
