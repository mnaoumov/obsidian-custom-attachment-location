import type { ClipboardManager } from '@obsidian-typings/obsidian-public-latest';

import { MonkeyAroundComponent } from '@mnaoumov/obsidian-lib/components/monkey-around-component';
import { getPrototypeOf } from '@mnaoumov/typescript-lib/object-utils';

import type { InsertGestureTrackerComponent } from './insert-gesture-tracker-component.ts';
import type { PastedImageMarker } from './pasted-image-marker.ts';

interface ClipboardManagerInsertFilesPatchComponentConstructorParams {
  readonly clipboardManager: ClipboardManager;
  readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;
  readonly pastedImageMarker: PastedImageMarker;
}

export class ClipboardManagerInsertFilesPatchComponent extends MonkeyAroundComponent {
  private readonly clipboardManager: ClipboardManager;
  private readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;
  private readonly pastedImageMarker: PastedImageMarker;

  public constructor(params: ClipboardManagerInsertFilesPatchComponentConstructorParams) {
    super();
    this.clipboardManager = params.clipboardManager;
    this.insertGestureTrackerComponent = params.insertGestureTrackerComponent;
    this.pastedImageMarker = params.pastedImageMarker;
  }

  public override onload(): void {
    this.registerMethodPatch({
      $object: getPrototypeOf(this.clipboardManager),
      methodName: 'insertFiles',
      patchHandler: async ({
        fallback,
        originalArguments: [importedAttachments]
      }) => {
        // `insertFiles` is where both an editor paste and an editor drop end up. Read the gesture before the first
        // `await`: the tracker forgets it as soon as the DOM event has been dispatched.
        const gesture = this.insertGestureTrackerComponent.gesture;
        await this.pastedImageMarker.record(importedAttachments, gesture);
        return fallback();
      }
    });
  }
}
