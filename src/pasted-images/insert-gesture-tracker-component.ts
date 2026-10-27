import { AllWindowsEventComponent } from '@mnaoumov/obsidian-lib/components/all-windows-event-component';

/**
 * The user gesture that brought files into Obsidian.
 */
export enum InsertGesture {
  Drop = 'Drop',
  Paste = 'Paste'
}

/**
 * Records which gesture, a paste or a drop, is being dispatched right now.
 *
 * Obsidian sends both gestures down one path: the editor's paste hook and its drop handler both call
 * `ClipboardManager.insertFiles`, and the canvas and the file explorer both call `App.importAttachments`. Neither
 * call says which gesture started it. Both are made synchronously inside the DOM event's dispatch, though (Obsidian
 * 1.14.4), so a capture-phase listener on every document sees the gesture first, and a patch that reads
 * {@link gesture} before its first `await` gets the right answer.
 *
 * The gesture is cleared on the next macrotask, after the dispatch has finished. A microtask would be too early:
 * the microtask checkpoint runs between listeners, before the editor's own handler gets the event.
 */
export class InsertGestureTrackerComponent extends AllWindowsEventComponent {
  /**
   * The gesture being dispatched, or `null` outside any paste or drop, for example when another plugin calls
   * `insertFiles` itself.
   *
   * @returns The current gesture.
   */
  public get gesture(): InsertGesture | null {
    return this._gesture;
  }

  private _gesture: InsertGesture | null = null;
  private gestureCount = 0;

  public override onload(): void {
    super.onload();
    this.registerAllDocumentsDomEvent({
      callback: () => {
        this.record(InsertGesture.Paste);
      },
      options: { capture: true },
      type: 'paste'
    });
    this.registerAllDocumentsDomEvent({
      callback: () => {
        this.record(InsertGesture.Drop);
      },
      options: { capture: true },
      type: 'drop'
    });
  }

  private record(gesture: InsertGesture): void {
    this._gesture = gesture;
    this.gestureCount++;
    const gestureCount = this.gestureCount;
    window.setTimeout(() => {
      // A later gesture owns the state now, and its own timer clears it.
      if (gestureCount === this.gestureCount) {
        this._gesture = null;
      }
    }, 0);
  }
}
