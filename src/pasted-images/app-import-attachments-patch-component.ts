import type { App } from 'obsidian';

import { MonkeyAroundComponent } from '@mnaoumov/obsidian-lib/components/monkey-around-component';

import type { InsertGestureTrackerComponent } from './insert-gesture-tracker-component.ts';
import type { PastedImageMarker } from './pasted-image-marker.ts';

import { InsertGesture } from './insert-gesture-tracker-component.ts';

interface AppImportAttachmentsPatchComponentConstructorParams {
  readonly app: App;
  readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;
  readonly pastedImageMarker: PastedImageMarker;
}

/**
 * Detects images pasted into a canvas.
 *
 * A canvas paste does not go through `ClipboardManager.insertFiles`: it calls `App.importAttachments`, which then
 * saves each file through `App.saveAttachment`. So does a drop onto a canvas, the file explorer or a base, and so
 * does the mobile share sheet. Only the paste is recorded here; a drop keeps its name, and the share sheet has
 * its own handling in `ShareReceiverImportFilesPatchComponent`.
 */
export class AppImportAttachmentsPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;
  private readonly pastedImageMarker: PastedImageMarker;

  public constructor(params: AppImportAttachmentsPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.insertGestureTrackerComponent = params.insertGestureTrackerComponent;
    this.pastedImageMarker = params.pastedImageMarker;
  }

  public override onload(): void {
    this.registerMethodPatch({
      $object: this.app,
      methodName: 'importAttachments',
      patchHandler: async ({
        fallback,
        originalArguments: [attachmentsToImport]
      }) => {
        // Read the gesture before the first `await`: the tracker forgets it as soon as the DOM event has been dispatched.
        if (this.insertGestureTrackerComponent.gesture === InsertGesture.Paste) {
          await this.pastedImageMarker.record(attachmentsToImport, InsertGesture.Paste);
        }
        return fallback();
      }
    });
  }
}
