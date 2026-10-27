import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import {
  InsertGesture,
  InsertGestureTrackerComponent
} from './insert-gesture-tracker-component.ts';

describe('InsertGestureTrackerComponent', () => {
  let tracker: InsertGestureTrackerComponent;

  beforeEach(() => {
    vi.useFakeTimers();
    tracker = new InsertGestureTrackerComponent(App.createConfigured__().asOriginalType__());
    tracker.load();
  });

  afterEach(() => {
    tracker.unload();
    vi.useRealTimers();
  });

  it('should report no gesture outside any paste or drop', () => {
    expect(tracker.gesture).toBeNull();
  });

  it('should report a paste while the paste is being dispatched, and forget it afterwards', () => {
    let gestureSeenByTarget: InsertGesture | null = null;
    const target = activeDocument.body.createDiv();
    target.addEventListener('paste', () => {
      gestureSeenByTarget = tracker.gesture;
    });

    target.dispatchEvent(new Event('paste', { bubbles: true }));

    expect(gestureSeenByTarget).toBe(InsertGesture.Paste);
    vi.runAllTimers();
    expect(tracker.gesture).toBeNull();
    target.remove();
  });

  it('should report a drop while the drop is being dispatched', () => {
    let gestureSeenByTarget: InsertGesture | null = null;
    const target = activeDocument.body.createDiv();
    target.addEventListener('drop', () => {
      gestureSeenByTarget = tracker.gesture;
    });

    target.dispatchEvent(new Event('drop', { bubbles: true }));

    expect(gestureSeenByTarget).toBe(InsertGesture.Drop);
    target.remove();
  });

  it('should keep the later gesture when an earlier gesture\'s timer fires', () => {
    const setTimeoutSpy = vi.spyOn(window, 'setTimeout');
    activeDocument.dispatchEvent(new Event('paste'));
    activeDocument.dispatchEvent(new Event('drop'));
    // Both timers are due at the same instant, so run the paste's alone to see what it does to the newer drop.
    const pasteTimerCallback = setTimeoutSpy.mock.calls[0]?.[0] as () => void;
    pasteTimerCallback();
    expect(tracker.gesture).toBe(InsertGesture.Drop);
    vi.runAllTimers();
    expect(tracker.gesture).toBeNull();
  });
});
