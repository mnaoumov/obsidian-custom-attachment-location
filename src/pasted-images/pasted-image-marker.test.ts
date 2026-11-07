import type { ImportedAttachment } from '@obsidian-typings/obsidian-public-latest';
import type { FileStats } from 'obsidian';

import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { ArrayBufferMap } from '../attachment-saving/array-buffer-map.ts';

import { NewAttachmentOperation } from '../attachment-saving/new-attachment-operation.ts';
import { InsertGesture } from './insert-gesture-tracker-component.ts';
import { PastedImageMarker } from './pasted-image-marker.ts';

describe('PastedImageMarker', () => {
  let fileStatsMap: Map<ArrayBuffer, FileStats>;
  let markAsPastedImageMock: ReturnType<typeof vi.fn<ArrayBufferMap['markAsPastedImage']>>;
  let operations: Map<ArrayBuffer, NewAttachmentOperation>;
  let trySetByPathMock: ReturnType<typeof vi.fn<ArrayBufferMap['trySetByPath']>>;
  let marker: PastedImageMarker;
  let shouldKeepNamesOfPastedNonScreenshotFiles: boolean;

  beforeEach(() => {
    fileStatsMap = new Map();
    operations = new Map();
    shouldKeepNamesOfPastedNonScreenshotFiles = true;
    markAsPastedImageMock = vi.fn<ArrayBufferMap['markAsPastedImage']>();
    trySetByPathMock = vi.fn<ArrayBufferMap['trySetByPath']>((arrayBuffer, filePath) => {
      if (filePath.includes('old')) {
        fileStatsMap.set(arrayBuffer, { ctime: 0, mtime: 0, size: arrayBuffer.byteLength });
      }
      return Promise.resolve(filePath !== '');
    });
    marker = new PastedImageMarker({
      arrayBufferMap: strictProxy<ArrayBufferMap>({
        getFileStats: (arrayBuffer: ArrayBuffer) => fileStatsMap.get(arrayBuffer),
        markAsPastedImage: markAsPastedImageMock,
        setNewAttachmentOperation: (arrayBuffer: ArrayBuffer, operation: NewAttachmentOperation): void => {
          operations.set(arrayBuffer, operation);
        },
        trySetByPath: trySetByPathMock
      }),
      getScreenshotFilePaths: (): readonly string[] => ['/PixPin_/'],
      getShouldKeepNamesOfPastedNonScreenshotFiles: (): boolean => shouldKeepNamesOfPastedNonScreenshotFiles
    });
  });

  function createAttachment(filepath: string | undefined, arrayBuffer: ArrayBuffer | null, extension = 'png'): ImportedAttachment {
    return {
      data: Promise.resolve(arrayBuffer),
      extension,
      ...(filepath !== undefined && { filepath }),
      name: 'attachment'
    };
  }

  it('should record the stats of every attachment and mark only the pasted images', async () => {
    const blob = new ArrayBuffer(1);
    const screenshot = new ArrayBuffer(2);
    const realFile = new ArrayBuffer(3);
    const pdf = new ArrayBuffer(4);

    await marker.record([
      createAttachment('', blob),
      createAttachment('C:/Temp/PixPin_old.png', screenshot),
      createAttachment('C:/Pictures/old.png', realFile),
      createAttachment('C:/Docs/old.pdf', pdf, 'pdf')
    ], InsertGesture.Paste);

    expect(trySetByPathMock).toHaveBeenCalledTimes(4);
    // Identity rather than `toHaveBeenCalledWith`: zero-filled buffers compare equal structurally.
    const markedBuffers = markAsPastedImageMock.mock.calls.map((call) => call[0]);
    expect(markedBuffers).toHaveLength(2);
    expect(markedBuffers[0]).toBe(blob);
    expect(markedBuffers[1]).toBe(screenshot);
    expect(operations.get(blob)).toBe(NewAttachmentOperation.PastedImage);
    expect(operations.get(screenshot)).toBe(NewAttachmentOperation.PastedImage);
    expect(operations.get(realFile)).toBe(NewAttachmentOperation.PastedFile);
    expect(operations.get(pdf)).toBe(NewAttachmentOperation.PastedFile);
  });

  it('should mark a pasted real file too while the names of non-screenshot files are not kept', async () => {
    shouldKeepNamesOfPastedNonScreenshotFiles = false;
    const realFile = new ArrayBuffer(3);
    await marker.record([createAttachment('C:/Pictures/old.png', realFile)], InsertGesture.Paste);
    expect(markAsPastedImageMock.mock.calls.map((call) => call[0])).toEqual([realFile]);
  });

  it('should mark nothing that was dropped with a path, and record it as a dropped file', async () => {
    const dropped = new ArrayBuffer(2);
    await marker.record([createAttachment('C:/Temp/PixPin_old.png', dropped)], InsertGesture.Drop);
    expect(markAsPastedImageMock).not.toHaveBeenCalled();
    expect(operations.get(dropped)).toBe(NewAttachmentOperation.DroppedFile);
  });

  it('should not classify anything as a pasted image when told it cannot be one', async () => {
    const blob = new ArrayBuffer(1);
    await marker.record([createAttachment(undefined, blob)], InsertGesture.Drop, false);
    expect(markAsPastedImageMock).not.toHaveBeenCalled();
    expect(operations.get(blob)).toBe(NewAttachmentOperation.DroppedFile);
  });

  it('should record no operation for an attachment inserted outside any gesture', async () => {
    const file = new ArrayBuffer(3);
    await marker.record([createAttachment('C:/Pictures/old.pdf', file, 'pdf')], null);
    expect(operations.has(file)).toBe(false);
  });

  it('should mark the clipboard-image fallback item, which carries no file path', async () => {
    const blob = new ArrayBuffer(1);
    await marker.record([createAttachment(undefined, blob)], InsertGesture.Paste);
    expect(trySetByPathMock).toHaveBeenCalledWith(blob, '');
    expect(markAsPastedImageMock.mock.calls.map((call) => call[0])).toEqual([blob]);
  });

  it('should skip an attachment whose content could not be read', async () => {
    await marker.record([createAttachment('C:/Unreadable.png', null)], InsertGesture.Paste);
    expect(trySetByPathMock).not.toHaveBeenCalled();
    expect(markAsPastedImageMock).not.toHaveBeenCalled();
  });

  it('should skip a folder, whose data is null', async () => {
    await marker.record([{
      data: null,
      extension: '',
      filepath: 'C:/Folder',
      isDirectory: true,
      name: 'Folder'
    }], InsertGesture.Paste);
    expect(trySetByPathMock).not.toHaveBeenCalled();
    expect(markAsPastedImageMock).not.toHaveBeenCalled();
  });
});
