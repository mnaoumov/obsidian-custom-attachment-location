import type { ImportedAttachment } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  TFile,
  TFolder
} from 'obsidian';

import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { InsertGestureTrackerComponent } from './insert-gesture-tracker-component.ts';
import type { PastedImageMarker } from './pasted-image-marker.ts';

import { AppImportAttachmentsPatchComponent } from './app-import-attachments-patch-component.ts';
import { InsertGesture } from './insert-gesture-tracker-component.ts';

interface GestureHolder {
  gesture: InsertGesture | null;
}

type ImportAttachmentsFunction = (attachmentsToImport: ImportedAttachment[], folder: null | TFolder) => Promise<TFile[]>;

interface ImportAttachmentsHolder {
  importAttachments: ImportAttachmentsFunction;
}

describe('AppImportAttachmentsPatchComponent', () => {
  let app: App;
  let gestureHolder: GestureHolder;
  let importAttachmentsMock: ReturnType<typeof vi.fn<ImportAttachmentsFunction>>;
  let recordMock: ReturnType<typeof vi.fn<PastedImageMarker['record']>>;

  beforeEach(() => {
    gestureHolder = { gesture: null };
    importAttachmentsMock = vi.fn<ImportAttachmentsFunction>().mockResolvedValue([]);
    app = strictProxy<App>({ importAttachments: importAttachmentsMock });
    recordMock = vi.fn<PastedImageMarker['record']>().mockResolvedValue(undefined);
  });

  function createComponent(): AppImportAttachmentsPatchComponent {
    return new AppImportAttachmentsPatchComponent({
      app,
      insertGestureTrackerComponent: strictProxy<InsertGestureTrackerComponent>({
        get gesture(): InsertGesture | null {
          return gestureHolder.gesture;
        }
      }),
      pastedImageMarker: strictProxy<PastedImageMarker>({ record: recordMock })
    });
  }

  async function importAttachments(attachments: ImportedAttachment[]): Promise<void> {
    await strictProxy<ImportAttachmentsHolder>(app).importAttachments(attachments, null);
  }

  const attachment: ImportedAttachment = {
    data: Promise.resolve(new ArrayBuffer(4)),
    extension: 'png',
    filepath: 'C:/Temp/PixPin_1.png',
    name: 'PixPin_1'
  };

  it('should record the attachments of a canvas paste, then delegate to the original method', async () => {
    createComponent().load();
    gestureHolder.gesture = InsertGesture.Paste;

    await importAttachments([attachment]);

    expect(recordMock).toHaveBeenCalledWith([attachment], InsertGesture.Paste);
    expect(importAttachmentsMock).toHaveBeenCalledWith([attachment], null);
  });

  it('should leave a drop alone', async () => {
    createComponent().load();
    gestureHolder.gesture = InsertGesture.Drop;

    await importAttachments([attachment]);

    expect(recordMock).not.toHaveBeenCalled();
    expect(importAttachmentsMock).toHaveBeenCalledTimes(1);
  });

  it('should leave a call outside any gesture alone', async () => {
    createComponent().load();

    await importAttachments([attachment]);

    expect(recordMock).not.toHaveBeenCalled();
    expect(importAttachmentsMock).toHaveBeenCalledTimes(1);
  });
});
