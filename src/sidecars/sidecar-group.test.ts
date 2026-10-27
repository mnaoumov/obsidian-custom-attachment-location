import { App } from 'obsidian-test-mocks/obsidian';
import {
  describe,
  expect,
  it,
  vi
} from 'vitest';

import {
  copyWithSidecars,
  getSidecarGroupPaths
} from './sidecar-group.ts';

describe('sidecar groups', () => {
  const extensions = ['p7s', 'asc', '.SRT'];

  it('connects chained signatures in both directions and keeps folders separate', () => {
    const paths = ['a/doc.html', 'a/doc.html.p7s', 'a/doc.html.p7s.asc', 'b/doc.html.p7s'];
    expect(getSidecarGroupPaths({ extensions, path: paths[1] ?? '', paths })).toEqual(paths.slice(0, 3));
  });

  it('leaves ambiguous and orphan sidecars independent', () => {
    const paths = ['doc.html', 'doc.pdf', 'doc.p7s', 'missing.asc'];
    expect(getSidecarGroupPaths({ extensions, path: 'doc.p7s', paths })).toEqual(['doc.p7s']);
    expect(getSidecarGroupPaths({ extensions, path: 'missing.asc', paths })).toEqual(['missing.asc']);
  });

  it('keeps separate companion groups in the same folder independent', () => {
    const paths = ['a.html', 'a.html.p7s', 'b.html', 'b.html.p7s'];
    expect(getSidecarGroupPaths({ extensions, path: 'a.html', paths })).toEqual(['a.html', 'a.html.p7s']);
  });

  it('copies bytes and chains beside the actual collision-suffixed base', async () => {
    const app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('out');
    await app.vault.create('video.mkv', 'base');
    await app.vault.create('video.srt', 'subtitle');
    await app.vault.create('video.srt.asc', 'signature');
    await app.vault.create('out/new.mkv', 'occupied');
    const path = await copyWithSidecars({ app, extensions, newPath: 'out/new.mkv', oldPathOrFile: 'video.mkv' });
    expect(path).not.toBe('out/new.mkv');
    const stem = path.slice(0, -4);
    expect(await app.vault.adapter.read(`${stem}.srt`)).toBe('subtitle');
    expect(await app.vault.adapter.read(`${stem}.srt.asc`)).toBe('signature');
    expect(await app.vault.adapter.read('video.srt')).toBe('subtitle');
  });

  it('refuses occupied companion destinations and removes the new base copy', async () => {
    const app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('out');
    await app.vault.create('doc.html', 'base');
    await app.vault.createBinary('doc.html.p7s', new TextEncoder().encode('signature').buffer);
    await app.vault.create('out/new.html.p7s', 'occupied');
    await expect(copyWithSidecars({ app, extensions, newPath: 'out/new.html', oldPathOrFile: 'doc.html' })).rejects.toThrow();
    expect(app.vault.getFileByPath('out/new.html')).toBeNull();
    expect(await app.vault.adapter.read('out/new.html.p7s')).toBe('occupied');
  });

  it('reuses identical companions when the base copy is reused', async () => {
    const app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('out');
    await app.vault.create('doc.html', 'base');
    await app.vault.createBinary('doc.html.p7s', new TextEncoder().encode('signature').buffer);
    const existingFile = await app.vault.create('out/new.html', 'base');
    await app.vault.createBinary('out/new.html.p7s', new TextEncoder().encode('signature').buffer);
    expect(await copyWithSidecars({ app, existingFile, extensions, newPath: existingFile.path, oldPathOrFile: 'doc.html' })).toBe(existingFile.path);
    expect(app.vault.getFiles()).toHaveLength(4);
  });

  it.each(['different', 'SIGNATURE', 'signature-longer'])('refuses a reused base with a conflicting companion: %s', async (content) => {
    const app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('out');
    await app.vault.create('doc.html', 'base');
    await app.vault.createBinary('doc.html.p7s', new TextEncoder().encode('signature').buffer);
    const existingFile = await app.vault.create('out/new.html', 'base');
    await app.vault.createBinary('out/new.html.p7s', new TextEncoder().encode(content).buffer);
    await expect(copyWithSidecars({ app, existingFile, extensions, newPath: existingFile.path, oldPathOrFile: 'doc.html' })).rejects.toThrow('Sidecar destination exists');
    expect(app.vault.getFileByPath(existingFile.path)).toBe(existingFile);
  });

  it('does not treat a destination folder as an identical companion', async () => {
    const app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('out');
    await app.vault.create('doc.html', 'base');
    await app.vault.create('doc.html.p7s', 'signature');
    const existingFile = await app.vault.create('out/new.html', 'base');
    await app.vault.createFolder('out/new.html.p7s');
    await expect(copyWithSidecars({ app, existingFile, extensions, newPath: existingFile.path, oldPathOrFile: 'doc.html' })).rejects.toThrow();
    expect(app.vault.getFileByPath(existingFile.path)).toBe(existingFile);
  });

  it('rolls back earlier copies when a later companion fails to copy', async () => {
    const app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('out');
    const file = await app.vault.create('doc.html', 'base');
    await app.vault.create('doc.html.p7s', 'signature');
    await app.vault.create('doc.html.p7s.asc', 'chain');
    const copy = app.vault.copy.bind(app.vault);
    vi.spyOn(app.vault, 'copy').mockImplementation(async (source, destination) => {
      if (destination.endsWith('.asc')) {
        throw new Error('disk failure');
      }
      return copy(source, destination);
    });
    await expect(copyWithSidecars({ app, extensions, newPath: 'out/new.html', oldPathOrFile: file })).rejects.toThrow('disk failure');
    expect(app.vault.getFiles().map((entry) => entry.path)).toEqual(['doc.html', 'doc.html.p7s', 'doc.html.p7s.asc']);
  });

  it('leaves a copy onto itself untouched', async () => {
    const app = App.createConfigured__().asOriginalType__();
    const file = await app.vault.create('doc.html', 'base');
    expect(await copyWithSidecars({ app, extensions: [], newPath: file.path, oldPathOrFile: file })).toBe(file.path);
    expect(app.vault.getFileByPath(file.path)).toBe(file);
    expect(getSidecarGroupPaths({ extensions: [], path: file.path, paths: [] })).toEqual([file.path]);
  });

  it('refuses companions whose generated destinations collide ignoring case', async () => {
    const app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('out');
    await app.vault.create('video.mkv', 'base');
    await app.vault.create('video.srt', 'subtitle');
    await app.vault.create('video.SRT', 'other subtitle');
    await expect(copyWithSidecars({ app, extensions, newPath: 'out/new.mkv', oldPathOrFile: 'video.mkv' })).rejects.toThrow('Sidecar destination exists');
    expect(app.vault.getFileByPath('out/new.mkv')).toBeNull();
  });

  it('rolls back a companion that acquired a collision suffix during the copy', async () => {
    const app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('out');
    await app.vault.create('doc.html', 'base');
    await app.vault.create('doc.html.p7s', 'signature');
    const vaultUtils = await import('@mnaoumov/obsidian-lib/vault');
    const copySafe = vaultUtils.copySafe;
    const copySpy = vi.spyOn(vaultUtils, 'copySafe').mockImplementation(async (params) => {
      if (params.newPath.endsWith('.p7s')) {
        await app.vault.create(params.newPath, 'racing file');
      }
      return copySafe(params);
    });
    try {
      await expect(copyWithSidecars({ app, extensions, newPath: 'out/new.html', oldPathOrFile: 'doc.html' })).rejects.toThrow('Sidecar destination changed');
    } finally {
      copySpy.mockRestore();
    }
    expect(app.vault.getFiles().filter((file) => file.path.startsWith('out/')).map((file) => file.path)).toEqual(['out/new.html.p7s']);
    expect(await app.vault.adapter.read('out/new.html.p7s')).toBe('racing file');
  });
});
