import type {
  ClipboardManager,
  ImportedAttachment
} from '@obsidian-typings/obsidian-public-latest';

import { noopAsync } from '@mnaoumov/typescript-lib/function';
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
  insertFiles: InsertFilesFunction;
}

interface GestureHolder {
  gesture: InsertGesture | null;
}

type InsertFilesFunction = (importedAttachments: ImportedAttachment[]) => Promise<void>;

describe('ClipboardManagerInsertFilesPatchComponent', () => {
  let gestureHolder: GestureHolder;
  let insertFilesMock: ReturnType<typeof vi.fn<InsertFilesFunction>>;
  let clipboardManager: ClipboardManager;
  let recordMock: ReturnType<typeof vi.fn<PastedImageMarker['record']>>;

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
      insertGestureTrackerComponent: strictProxy<InsertGestureTrackerComponent>({ gesture: InsertGesture.Drop }),
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
    clipboardManager = strictProxy<ClipboardManager>(Object.create(clipboardManagerPrototype));
    recordMock = vi.fn<PastedImageMarker['record']>().mockResolvedValue(undefined);
  });

  function createComponent(): ClipboardManagerInsertFilesPatchComponent {
    return new ClipboardManagerInsertFilesPatchComponent({
      clipboardManager,
      insertGestureTrackerComponent: strictProxy<InsertGestureTrackerComponent>({
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
