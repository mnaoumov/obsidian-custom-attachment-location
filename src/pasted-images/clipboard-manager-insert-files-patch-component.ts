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

interface PendingEmbeds {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Counts the batches in flight, so it changes as each starts and ends.
  depth: number;
  readonly texts: string[];
}

export class ClipboardManagerInsertFilesPatchComponent extends MonkeyAroundComponent {
  private readonly clipboardManager: ClipboardManager;
  private readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;
  private readonly pastedImageMarker: PastedImageMarker;
  /**
   * The embeds of the batch each clipboard manager is inserting, written to its editor once the whole batch is saved.
   */
  private readonly pendingEmbedsByClipboardManager = new WeakMap<ClipboardManager, PendingEmbeds>();
  private readonly sidecarAttachmentsComponent: SidecarAttachmentsComponent | undefined;

  public constructor(params: ClipboardManagerInsertFilesPatchComponentConstructorParams) {
    super();
    this.clipboardManager = params.clipboardManager;
    this.insertGestureTrackerComponent = params.insertGestureTrackerComponent;
    this.pastedImageMarker = params.pastedImageMarker;
    this.sidecarAttachmentsComponent = params.sidecarAttachmentsComponent;
  }

  public override onload(): void {
    const prototype = getPrototypeOf(this.clipboardManager);
    this.registerMethodPatch({
      $object: prototype,
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
        await this.runBatch(originalThis, async () => {
          await (this.sidecarAttachmentsComponent ? this.sidecarAttachmentsComponent.runImportBatch(importedAttachments, fallback) : fallback());
        });
      }
    });

    this.registerMethodPatch({
      $object: prototype,
      methodName: 'insertAttachmentEmbed',
      patchHandler: ({ fallback, originalThis }) => {
        const pendingEmbeds = this.pendingEmbedsByClipboardManager.get(originalThis);
        if (!pendingEmbeds) {
          return fallback();
        }

        // Core builds the embed text and hands it straight to `replaceSelection`, synchronously (Obsidian 1.15.1;
        // the typings say it returns a promise, but nothing in it awaits). Catch that one call, so the text joins the
        // batch rather than the document; nothing else can run while the swap is in place.
        const editor = originalThis.info.editor;
        const hasOwnReplaceSelection = Object.hasOwn(editor, 'replaceSelection');
        // eslint-disable-next-line @typescript-eslint/unbound-method -- Put back exactly as found.
        const ownReplaceSelection = editor.replaceSelection;
        editor.replaceSelection = (replacement: string): void => {
          pendingEmbeds.texts.push(replacement);
        };
        try {
          return fallback();
        } finally {
          if (hasOwnReplaceSelection) {
            editor.replaceSelection = ownReplaceSelection;
          } else {
            Reflect.deleteProperty(editor, 'replaceSelection');
          }
        }
      }
    });
  }

  /**
   * Runs one `insertFiles` batch, and writes all of its embeds into the editor in one transaction once every file is
   * saved.
   *
   * Core saves the files one after another and writes each embed as soon as its file is saved, so a batch arrived in
   * the note one link at a time, typing could land between two of them, and undoing it took one step per file. A
   * second batch started on the same editor before the first finishes joins it, and both are written when the last
   * one ends.
   *
   * @param clipboardManager - The clipboard manager inserting the batch.
   * @param run - Saves the batch.
   */
  private async runBatch(clipboardManager: ClipboardManager, run: () => Promise<void>): Promise<void> {
    let pendingEmbeds = this.pendingEmbedsByClipboardManager.get(clipboardManager);
    if (!pendingEmbeds) {
      pendingEmbeds = { depth: 0, texts: [] };
      this.pendingEmbedsByClipboardManager.set(clipboardManager, pendingEmbeds);
    }
    pendingEmbeds.depth++;
    try {
      await run();
    } finally {
      pendingEmbeds.depth--;
      if (pendingEmbeds.depth === 0) {
        this.pendingEmbedsByClipboardManager.delete(clipboardManager);
        if (pendingEmbeds.texts.length > 0) {
          clipboardManager.info.editor.replaceSelection(pendingEmbeds.texts.join(''));
        }
      }
    }
  }
}
