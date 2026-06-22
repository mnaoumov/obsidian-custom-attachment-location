import type {
  App,
  CapacitorAdapter as CapacitorAdapterType,
  FileStats,
  FileSystemAdapter as FileSystemAdapterType
} from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  CapacitorAdapter,
  FileSystemAdapter
} from 'obsidian-test-mocks/obsidian';
import {
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { ArrayBufferMap } from './array-buffer-map.ts';

type CapacitorFs = CapacitorAdapterType['fs'];
type FsPromises = FileSystemAdapterType['fsPromises'];
type FsStat = (path: string) => ReturnType<FsPromises['stat']>;
type FsStats = Awaited<ReturnType<FsPromises['stat']>>;

function createApp(adapter: App['vault']['adapter']): App {
  return strictProxy<App>({
    vault: strictProxy<App['vault']>({
      adapter
    })
  });
}

function createCapacitorAdapter(fs: CapacitorFs): CapacitorAdapterType {
  const adapter = CapacitorAdapter.create__('/mock-vault', fs).asOriginalType__();
  adapter.fs = fs;
  return adapter;
}

function createFileSystemAdapter(fsPromises: FsPromises): FileSystemAdapterType {
  const adapter = FileSystemAdapter.create__('/mock-vault').asOriginalType__();
  adapter.fsPromises = fsPromises;
  return adapter;
}

describe('ArrayBufferMap', () => {
  describe('getFileStats/setFileStats', () => {
    it('should return undefined for an unknown array buffer', () => {
      const map = new ArrayBufferMap({ app: strictProxy<App>({}) });
      expect(map.getFileStats(new ArrayBuffer(0))).toBeUndefined();
    });

    it('should store and retrieve file stats for an array buffer', () => {
      const map = new ArrayBufferMap({ app: strictProxy<App>({}) });
      const arrayBuffer = new ArrayBuffer(8);
      const fileStats: FileStats = { ctime: 1, mtime: 2, size: 8 };
      map.setFileStats(arrayBuffer, fileStats);
      expect(map.getFileStats(arrayBuffer)).toBe(fileStats);
    });
  });

  describe('trySetByPath', () => {
    it('should return false for an empty path', async () => {
      const map = new ArrayBufferMap({ app: strictProxy<App>({}) });
      const arrayBuffer = new ArrayBuffer(8);
      expect(await map.trySetByPath(arrayBuffer, '')).toBe(false);
      expect(map.getFileStats(arrayBuffer)).toBeUndefined();
    });

    it('should set file stats from the FileSystemAdapter', async () => {
      const stat = vi.fn<FsStat>().mockResolvedValue(castTo<FsStats>({
        ctimeMs: 111,
        mtimeMs: 222,
        size: 333
      }));
      const fsPromises = castTo<FsPromises>({ stat });
      const map = new ArrayBufferMap({ app: createApp(createFileSystemAdapter(fsPromises)) });
      const arrayBuffer = new ArrayBuffer(8);

      expect(await map.trySetByPath(arrayBuffer, 'file.png')).toBe(true);
      expect(stat).toHaveBeenCalledWith('file.png');
      expect(map.getFileStats(arrayBuffer)).toStrictEqual({ ctime: 111, mtime: 222, size: 333 });
    });

    it('should set file stats from the CapacitorAdapter', async () => {
      const stat = vi.fn<CapacitorFs['stat']>().mockResolvedValue({
        ctime: 444,
        mtime: 555,
        name: 'file.png',
        size: 999,
        type: 'file',
        uri: 'file://file.png'
      });
      const fs = strictProxy<CapacitorFs>({ stat });
      const map = new ArrayBufferMap({ app: createApp(createCapacitorAdapter(fs)) });
      const arrayBuffer = new ArrayBuffer(8);

      expect(await map.trySetByPath(arrayBuffer, 'file.png')).toBe(true);
      expect(stat).toHaveBeenCalledWith('file.png');
      expect(map.getFileStats(arrayBuffer)).toStrictEqual({ ctime: 444, mtime: 555, size: 8 });
    });

    it('should fall back to zero ctime/mtime when the CapacitorAdapter omits the times', async () => {
      const stat = vi.fn<CapacitorFs['stat']>().mockResolvedValue({
        name: 'file.png',
        type: 'file',
        uri: 'file://file.png'
      });
      const fs = strictProxy<CapacitorFs>({ stat });
      const map = new ArrayBufferMap({ app: createApp(createCapacitorAdapter(fs)) });
      const arrayBuffer = new ArrayBuffer(4);

      expect(await map.trySetByPath(arrayBuffer, 'file.png')).toBe(true);
      expect(map.getFileStats(arrayBuffer)).toStrictEqual({ ctime: 0, mtime: 0, size: 4 });
    });

    it('should return false when the adapter is neither a FileSystemAdapter nor a CapacitorAdapter', async () => {
      const map = new ArrayBufferMap({ app: createApp(strictProxy<App['vault']['adapter']>({})) });
      const arrayBuffer = new ArrayBuffer(8);

      expect(await map.trySetByPath(arrayBuffer, 'file.png')).toBe(false);
      expect(map.getFileStats(arrayBuffer)).toBeUndefined();
    });
  });
});
