import type {
  ClipboardManager,
  ImportedAttachment
} from '@obsidian-typings/obsidian-public-latest';

import { noopAsync } from '@mnaoumov/typescript-lib/function';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { SidecarAttachmentsComponent } from '../sidecars/sidecar-attachments-component.ts';
import type { InsertGestureTrackerComponent } from './insert-gesture-tracker-component.ts';
import type { PastedImageMarker } from './pasted-image-marker.ts';

import { ClipboardManagerInsertFilesPatchComponent } from './clipboard-manager-insert-files-patch-component.ts';
import { InsertGesture } from './insert-gesture-tracker-component.ts';

interface ClipboardManagerPrototype {
  readonly insertFiles: InsertFilesFunction;
}

interface GestureHolder {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  gesture: InsertGesture | null;
}

type InsertFilesFunction = (importedAttachments: ImportedAttachment[]) => Promise<void>;

class FakeDoc {
  public readonly length: number;

  public constructor(private readonly text: string) {
    this.length = text.length;
  }

  public sliceString(from: number, to: number): string {
    return this.text.slice(from, to);
  }

  public toString(): string {
    return this.text;
  }
}

class FakeState {
  public get selection(): unknown {
    return this.getSelection();
  }

  public constructor(public readonly doc: FakeDoc, private readonly getSelection: () => unknown) {}
}

const NOTE_TEXT = '---\ntags: a\n---\nBody line\n';
const BODY_START = NOTE_TEXT.indexOf('Body');

describe('ClipboardManagerInsertFilesPatchComponent', () => {
  let gestureHolder: GestureHolder;
  let insertFilesMock: ReturnType<typeof vi.fn<InsertFilesFunction>>;
  let clipboardManager: ClipboardManager;
  let recordMock: ReturnType<typeof vi.fn<PastedImageMarker['record']>>;
  let editorDispatchMock: ReturnType<typeof vi.fn>;
  let editorSelection: unknown;

  function createSelection(position: number): unknown {
    return { ranges: [{ from: position, to: position }] };
  }

  it('puts a drop that Obsidian moved above the frontmatter back where the cursor was, before anything is inserted', async () => {
    const component = createComponent();
    component.load();
    gestureHolder.gesture = InsertGesture.Drop;
    const selectionBeforeDrop = createSelection(BODY_START + 2);
    editorSelection = selectionBeforeDrop;
    insertFilesMock.mockImplementation(() => {
      expect(editorDispatchMock).toHaveBeenCalledWith({ selection: selectionBeforeDrop });
      return noopAsync();
    });

    const promise = strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles([createAttachment('a.png')]);
    // What Obsidian's drop handler does right after insertFiles returns, for a drop on the Properties block.
    editorSelection = createSelection(0);
    gestureHolder.gesture = null;
    await promise;

    expect(insertFilesMock).toHaveBeenCalledTimes(1);
  });

  it('does not touch the selection for a paste', async () => {
    const component = createComponent();
    component.load();
    gestureHolder.gesture = InsertGesture.Paste;
    editorSelection = createSelection(0);

    await strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles([createAttachment('a.png')]);

    expect(editorDispatchMock).not.toHaveBeenCalled();
  });

  it('keeps sidecar batch handling around the full editor import after gesture recording', async () => {
    const trace: string[] = [];
    const attachments = [createAttachment('doc.html'), createAttachment('doc.html.p7s')];
    recordMock.mockImplementation(() => {
      trace.push('gesture');
      return noopAsync();
    });
    async function runImportBatch<T>(items: readonly ImportedAttachment[], run: () => Promise<T>): Promise<T> {
      expect(items).toBe(attachments);
      trace.push('batch-start');
      const result = await run();
      trace.push('batch-end');
      return result;
    }
    insertFilesMock.mockImplementation(() => {
      trace.push('save');
      return noopAsync();
    });
    const component = new ClipboardManagerInsertFilesPatchComponent({
      clipboardManager,
      insertGestureTrackerComponent: strictProxy<InsertGestureTrackerComponent>({ dropClientY: null, gesture: InsertGesture.Drop }),
      pastedImageMarker: strictProxy<PastedImageMarker>({ record: recordMock }),
      sidecarAttachmentsComponent: strictProxy<SidecarAttachmentsComponent>({ runImportBatch })
    });
    component.load();
    await clipboardManager.insertFiles(attachments);
    expect(trace).toEqual(['gesture', 'batch-start', 'save', 'batch-end']);
  });

  beforeEach(() => {
    gestureHolder = { gesture: null };
    insertFilesMock = vi.fn<InsertFilesFunction>().mockResolvedValue(undefined);
    const clipboardManagerPrototype: ClipboardManagerPrototype = {
      insertFiles: insertFilesMock
    };
    const clipboardManagerObject = castTo<Record<string, unknown>>(Object.create(clipboardManagerPrototype));
    editorDispatchMock = vi.fn();
    editorSelection = createSelection(BODY_START);
    clipboardManagerObject['info'] = {
      editor: {
        activeCM: {
          dispatch: editorDispatchMock,
          documentTop: 0,
          // Class instances, not plain objects: the strict proxy would answer `toString` itself and cache the
          // selection it read first.
          state: new FakeState(new FakeDoc(NOTE_TEXT), () => editorSelection)
        }
      }
    };
    clipboardManager = strictProxy<ClipboardManager>(clipboardManagerObject);
    recordMock = vi.fn<PastedImageMarker['record']>().mockResolvedValue(undefined);
  });

  function createComponent(): ClipboardManagerInsertFilesPatchComponent {
    return new ClipboardManagerInsertFilesPatchComponent({
      clipboardManager,
      insertGestureTrackerComponent: strictProxy<InsertGestureTrackerComponent>({
        dropClientY: null,
        get gesture(): InsertGesture | null {
          return gestureHolder.gesture;
        }
      }),
      pastedImageMarker: strictProxy<PastedImageMarker>({ record: recordMock })
    });
  }

  function createAttachment(filepath: string): ImportedAttachment {
    return {
      data: Promise.resolve(new ArrayBuffer(4)),
      extension: 'png',
      filepath,
      name: 'attachment'
    };
  }

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should record the attachments with the gesture in progress, then delegate to the original method', async () => {
    const component = createComponent();
    component.load();
    gestureHolder.gesture = InsertGesture.Drop;

    const attachments = [createAttachment('folder/a.png'), createAttachment('folder/b.png')];
    const promise = strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles(attachments);
    // The gesture is read synchronously, before the tracker forgets it.
    gestureHolder.gesture = null;
    await promise;

    expect(recordMock).toHaveBeenCalledWith(attachments, InsertGesture.Drop);
    expect(insertFilesMock).toHaveBeenCalledWith(attachments);
  });

  it('should record with no gesture when insertFiles is called outside a paste or drop', async () => {
    const component = createComponent();
    component.load();

    await strictProxy<ClipboardManagerPrototype>(clipboardManager).insertFiles([]);

    expect(recordMock).toHaveBeenCalledWith([], null);
    expect(insertFilesMock).toHaveBeenCalledTimes(1);
  });
});
