import type {
  ClipboardManager,
  ImportedAttachment
} from '@obsidian-typings/obsidian-public-latest';

import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { ArrayBufferMap } from '../array-buffer-map.ts';

import { ClipboardManagerInsertFilesPatchComponent } from './clipboard-manager-insert-files-patch-component.ts';

interface ClipboardManagerProto {
  insertFiles: InsertFilesFn;
}

type InsertFilesFn = (importedAttachments: ImportedAttachment[]) => Promise<void>;

describe('ClipboardManagerInsertFilesPatchComponent', () => {
  let arrayBufferMap: ArrayBufferMap;
  let insertFilesMock: ReturnType<typeof vi.fn<InsertFilesFn>>;
  let clipboardManagerProto: ClipboardManagerProto;
  let clipboardManager: ClipboardManager;

  beforeEach(() => {
    arrayBufferMap = strictProxy<ArrayBufferMap>({
      trySetByPath: vi.fn().mockResolvedValue(true)
    });
    insertFilesMock = vi.fn<InsertFilesFn>().mockResolvedValue(undefined);
    clipboardManagerProto = {
      insertFiles: insertFilesMock
    };
    clipboardManager = strictProxy<ClipboardManager>(Object.create(clipboardManagerProto));
  });

  function createComponent(): ClipboardManagerInsertFilesPatchComponent {
    return new ClipboardManagerInsertFilesPatchComponent({
      arrayBufferMap,
      clipboardManager
    });
  }

  function createAttachment(filepath: string, buffer: ArrayBuffer): ImportedAttachment {
    return {
      data: Promise.resolve(buffer),
      extension: 'png',
      filepath,
      name: 'attachment.png'
    };
  }

  it('should register a single method patch on load', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should record each attachment by path and delegate to the original method', async () => {
    const component = createComponent();
    component.load();

    const buffer1 = new ArrayBuffer(4);
    const buffer2 = new ArrayBuffer(8);
    const attachments = [
      createAttachment('folder/a.png', buffer1),
      createAttachment('folder/b.png', buffer2)
    ];

    await strictProxy<ClipboardManagerProto>(clipboardManager).insertFiles(attachments);

    expect(vi.mocked(arrayBufferMap.trySetByPath)).toHaveBeenCalledWith(buffer1, 'folder/a.png');
    expect(vi.mocked(arrayBufferMap.trySetByPath)).toHaveBeenCalledWith(buffer2, 'folder/b.png');
    expect(insertFilesMock).toHaveBeenCalledWith(attachments);
  });

  it('should still delegate to the original method when there are no attachments', async () => {
    const component = createComponent();
    component.load();

    await strictProxy<ClipboardManagerProto>(clipboardManager).insertFiles([]);

    expect(vi.mocked(arrayBufferMap.trySetByPath)).not.toHaveBeenCalled();
    expect(insertFilesMock).toHaveBeenCalledTimes(1);
  });
});
