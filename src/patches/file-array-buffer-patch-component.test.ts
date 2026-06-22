import type {
  App as AppOriginal,
  DataAdapter
} from 'obsidian';

import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { ArrayBufferMap } from '../array-buffer-map.ts';

import { FileArrayBufferPatchComponent } from './file-array-buffer-patch-component.ts';

interface WebUtilsMock {
  getPathForFile(file: File): string;
}

interface WebUtilsModule {
  webUtils: WebUtilsMock;
}

const getPathForFileMock = vi.fn<(file: File) => string>();

vi.mock('electron', (): WebUtilsModule => {
  return {
    webUtils: {
      getPathForFile: (file: File): string => getPathForFileMock(file)
    }
  };
});

describe('FileArrayBufferPatchComponent', () => {
  let arrayBufferMap: ArrayBufferMap;
  let file: File;
  let fallbackArrayBuffer: ArrayBuffer;

  beforeEach(() => {
    getPathForFileMock.mockReset();
    getPathForFileMock.mockReturnValue('/vault/note.png');
    fallbackArrayBuffer = new ArrayBuffer(16);
    arrayBufferMap = strictProxy<ArrayBufferMap>({
      setFileStats: vi.fn(),
      trySetByPath: vi.fn().mockResolvedValue(false)
    });
    file = strictProxy<File>({
      arrayBuffer: vi.fn().mockResolvedValue(fallbackArrayBuffer),
      lastModified: 123,
      size: 16
    });
  });

  function createComponent(app: AppOriginal): FileArrayBufferPatchComponent {
    return new FileArrayBufferPatchComponent({
      app,
      arrayBufferMap,
      file
    });
  }

  function createFileSystemApp(): AppOriginal {
    return App.createConfigured__().asOriginalType__();
  }

  function createNonFileSystemApp(): AppOriginal {
    const app = App.createConfigured__();
    app.vault.adapter = strictProxy<DataAdapter>({});
    return app.asOriginalType__();
  }

  it('should register a single method patch on load', () => {
    const component = createComponent(createFileSystemApp());
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(1);
  });

  it('should return the array buffer immediately when the stats were recorded by path', async () => {
    vi.mocked(arrayBufferMap.trySetByPath).mockResolvedValue(true);
    const component = createComponent(createFileSystemApp());
    component.load();

    const result = await file.arrayBuffer();

    expect(result).toBe(fallbackArrayBuffer);
    expect(getPathForFileMock).toHaveBeenCalledWith(file);
    expect(vi.mocked(arrayBufferMap.trySetByPath)).toHaveBeenCalledWith(fallbackArrayBuffer, '/vault/note.png');
    expect(vi.mocked(arrayBufferMap.setFileStats)).not.toHaveBeenCalled();
  });

  it('should fall back to setting file stats when the path lookup fails on a file system adapter', async () => {
    vi.mocked(arrayBufferMap.trySetByPath).mockResolvedValue(false);
    const component = createComponent(createFileSystemApp());
    component.load();

    const result = await file.arrayBuffer();

    expect(result).toBe(fallbackArrayBuffer);
    expect(vi.mocked(arrayBufferMap.setFileStats)).toHaveBeenCalledWith(fallbackArrayBuffer, {
      ctime: 0,
      mtime: 123,
      size: 16
    });
  });

  it('should set file stats without trying the path when the adapter is not a file system adapter', async () => {
    const component = createComponent(createNonFileSystemApp());
    component.load();

    const result = await file.arrayBuffer();

    expect(result).toBe(fallbackArrayBuffer);
    expect(getPathForFileMock).not.toHaveBeenCalled();
    expect(vi.mocked(arrayBufferMap.trySetByPath)).not.toHaveBeenCalled();
    expect(vi.mocked(arrayBufferMap.setFileStats)).toHaveBeenCalledWith(fallbackArrayBuffer, {
      ctime: 0,
      mtime: 123,
      size: 16
    });
  });
});
