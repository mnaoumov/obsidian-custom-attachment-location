import type { ClipboardManager } from '@obsidian-typings/obsidian-public-latest';

import { MonkeyAroundComponent } from '@mnaoumov/obsidian-lib/components/monkey-around-component';
import { getPrototypeOf } from '@mnaoumov/typescript-lib/object-utils';

import type { SidecarAttachmentsComponent } from '../sidecars/sidecar-attachments-component.ts';
import type { InsertGestureTrackerComponent } from './insert-gesture-tracker-component.ts';
import type { PastedImageMarker } from './pasted-image-marker.ts';

import { keepDropInsertPositionInBody } from './drop-insert-position.ts';
import { InsertGesture } from './insert-gesture-tracker-component.ts';

interface ClipboardManagerInsertFilesPatchComponentConstructorParams {
  readonly clipboardManager: ClipboardManager;
  readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;
  readonly pastedImageMarker: PastedImageMarker;
  readonly sidecarAttachmentsComponent?: SidecarAttachmentsComponent;
}

export class ClipboardManagerInsertFilesPatchComponent extends MonkeyAroundComponent {
  private readonly clipboardManager: ClipboardManager;
  private readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;
  private readonly pastedImageMarker: PastedImageMarker;
  private readonly sidecarAttachmentsComponent: SidecarAttachmentsComponent | undefined;

  public constructor(params: ClipboardManagerInsertFilesPatchComponentConstructorParams) {
    super();
    this.clipboardManager = params.clipboardManager;
    this.insertGestureTrackerComponent = params.insertGestureTrackerComponent;
    this.pastedImageMarker = params.pastedImageMarker;
    this.sidecarAttachmentsComponent = params.sidecarAttachmentsComponent;
  }

  public override onload(): void {
    this.registerMethodPatch({
      $object: getPrototypeOf(this.clipboardManager),
      methodName: 'insertFiles',
      patchHandler: async ({
        fallback,
        originalArguments: [importedAttachments],
        originalThis
      }) => {
        // `insertFiles` is where both an editor paste and an editor drop end up. Read the gesture before the first
        // `await`: the tracker forgets it as soon as the DOM event has been dispatched.
        const gesture = this.insertGestureTrackerComponent.gesture;
        const dropClientY = this.insertGestureTrackerComponent.dropClientY;
        // Obsidian's drop handler calls `insertFiles` BEFORE it moves the selection to the drop point, so the
        // selection read here is still the one the user had.
        const dropEditorView = gesture === InsertGesture.Drop ? originalThis.info.editor.activeCM : null;
        const selectionBeforeDrop = dropEditorView?.state.selection ?? null;
        await this.pastedImageMarker.record(importedAttachments, gesture);
        // By now the drop handler has moved the selection, and nothing has been inserted yet.
        if (dropEditorView && selectionBeforeDrop) {
          keepDropInsertPositionInBody({ dropClientY, selectionBeforeDrop, view: dropEditorView });
        }
        await (this.sidecarAttachmentsComponent ? this.sidecarAttachmentsComponent.runImportBatch(importedAttachments, fallback) : fallback());
      }
    });
  }
}
