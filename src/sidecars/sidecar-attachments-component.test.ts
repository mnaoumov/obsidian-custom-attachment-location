// Cspell:words УХВАЛА
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { ImportedAttachment } from '@obsidian-typings/obsidian-public-latest';
import type { TFile } from 'obsidian';

import { AttachmentPathContext } from '@mnaoumov/obsidian-lib/attachment-path';
import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentPathManager } from '../attachment-location/attachment-path-manager.ts';
import type { AttachmentSaver } from '../attachment-saving/attachment-saver.ts';
import type { OriginalAttachmentNamesComponent } from '../original-attachment-names/original-attachment-names-component.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { PluginSettings } from '../settings/plugin-settings.ts';
import { ActionContext } from '../tokens/token-evaluator-context.ts';
import { SidecarAttachmentsComponent } from './sidecar-attachments-component.ts';

describe('sidecar attachment operations', () => {
  let app: ReturnType<App['asOriginalType__']>;
  let component: SidecarAttachmentsComponent;
  let saver: AttachmentSaver;
  let settings: PluginSettings;
  let pathManager: AttachmentPathManager;
  let originalNames: Map<string, string>;
  let originalPaths: Map<string, string>;
  let save: ReturnType<typeof vi.fn<AttachmentSaver['saveAttachment']>>;
  let showNotice: ReturnType<typeof vi.fn<PluginNoticeComponent['showNotice']>>;

  beforeAll(async () => {
    await initI18N(translationsMap);
  });
  beforeEach(async () => {
    app = App.createConfigured__().asOriginalType__();
    await app.vault.createFolder('assets');
    settings = new PluginSettings();
    showNotice = vi.fn();
    let sequence = 0;
    save = vi.fn<AttachmentSaver['saveAttachment']>(async (params) => {
      sequence++;
      const name = params.shouldKeepName ? params.attachmentFileBaseName : `random-${sequence.toString()}`;
      return await app.vault.createBinary(params.destinationPath ?? `assets/${name}.${params.attachmentFileExtension}`, params.attachmentFileContent);
    });
    saver = strictProxy<AttachmentSaver>({ saveAttachment: save });
    originalNames = new Map();
    originalPaths = new Map();
    pathManager = strictProxy<AttachmentPathManager>({
      getAttachmentFolderFullPathForPath: vi.fn().mockResolvedValue('assets'),
      getAvailablePathForAttachments: vi.fn().mockResolvedValue('assets/independent.pdf'),
      getProperAttachmentPath: vi.fn().mockResolvedValue('assets/independent.pdf'),
      originalAttachmentNamesComponent: strictProxy<OriginalAttachmentNamesComponent>({
        get: (path) => originalNames.get(path),
        setOriginalPath: (path, originalPath) => {
          originalPaths.set(path, originalPath);
        }
      })
    });
    app.importAttachments = async (attachments): Promise<TFile[]> => {
      const files: TFile[] = [];
      for (const attachment of attachments) {
        const content = await attachment.data;
        if (content) {
          files.push(await saver.saveAttachment({ attachmentFileBaseName: attachment.name, attachmentFileContent: content, attachmentFileExtension: attachment.extension }));
        }
      }
      return files;
    };
    component = new SidecarAttachmentsComponent({
      app,
      attachmentPathManager: pathManager,
      attachmentSaver: saver,
      pluginNoticeComponent: strictProxy<PluginNoticeComponent>({ showNotice }),
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings })
    });
    component.load();
  });
  afterEach(() => {
    component.unload();
  });

  it('retains each import source path even when its destination name changes', async () => {
    const files = await app.importAttachments([imported('source', 'pdf', '/Downloads/source.pdf')], null);
    expect(files).toHaveLength(1);
    expect(originalPaths.get(files[0]?.path ?? '')).toBe('/Downloads/source.pdf');
  });

  function imported(name: string, extension: string, filepath?: string): ImportedAttachment {
    return { data: Promise.resolve(new TextEncoder().encode(name + extension).buffer), extension, name, ...filepath && { filepath } };
  }

  it.each([false, true])('uses one base save even when the signature comes first (%s)', async (isReversed) => {
    const attachments = [imported('УХВАЛА', 'html'), imported('УХВАЛА.html', 'p7s')];
    const files = await app.importAttachments(isReversed ? attachments.reverse() : attachments, null);
    expect(files.map((file) => file.path).sort()).toEqual(['assets/random-1.html', 'assets/random-1.html.p7s']);
    expect(save).toHaveBeenCalledTimes(2);
    expect(showNotice).not.toHaveBeenCalled();
  });

  it('uses the same stem for subtitles', async () => {
    const files = await app.importAttachments([imported('video', 'srt'), imported('video', 'mkv')], null);
    expect(files.map((file) => file.path)).toEqual(['assets/random-1.srt', 'assets/random-1.mkv']);
  });

  it('keeps and reports a signature whose base is absent', async () => {
    const files = await app.importAttachments([imported('missing.html', 'p7s')], null);
    expect(files[0]?.path).toBe('assets/missing.html.p7s');
    expect(showNotice).toHaveBeenCalledWith(expect.stringContaining('missing.html.p7s'));
  });

  it('does not pair equal names from different source directories', async () => {
    const files = await app.importAttachments([imported('report', 'html', '/one/report.html'), imported('report.html', 'p7s', '/two/report.html.p7s')], null);
    expect(files[1]?.path).toBe('assets/report.html.p7s');
    expect(showNotice).toHaveBeenCalledOnce();
  });

  it('renames and moves unlinked signatures and subtitles with their base', async () => {
    const base = await app.vault.create('assets/video.mkv', 'video');
    await app.vault.create('assets/video.mkv.p7s', 'signature');
    await app.vault.create('assets/video.srt', 'subtitle');
    await app.vault.rename(base, 'renamed.mkv');
    expect(base.path).toBe('renamed.mkv');
    expect(app.vault.getFileByPath('renamed.mkv.p7s')).not.toBeNull();
    expect(app.vault.getFileByPath('renamed.srt')).not.toBeNull();
    expect(app.vault.getFileByPath('assets/video.srt')).toBeNull();
  });

  it('refuses an occupied companion destination before moving the base', async () => {
    const base = await app.vault.create('assets/report.html', 'base');
    await app.vault.create('assets/report.html.p7s', 'signature');
    await app.vault.create('taken.html.p7s', 'other signature');
    const rename = vi.spyOn(app.fileManager, 'renameFile');
    await expect(app.vault.rename(base, 'taken.html')).rejects.toThrow('already exists');
    expect(base.path).toBe('assets/report.html');
    expect(await app.vault.adapter.read('taken.html.p7s')).toBe('other signature');
    expect(rename).not.toHaveBeenCalled();
  });

  it('restores the base when a companion move fails', async () => {
    const base = await app.vault.create('assets/report.html', 'base');
    await app.vault.create('assets/report.html.p7s', 'signature');
    vi.spyOn(app.fileManager, 'renameFile').mockRejectedValueOnce(new Error('disk failure'));
    await expect(app.vault.rename(base, 'renamed.html')).rejects.toThrow('disk failure');
    expect(base.path).toBe('assets/report.html');
    expect(app.vault.getFileByPath('assets/report.html.p7s')).not.toBeNull();
  });

  it('leaves ordinary files independent when pairing is disabled', async () => {
    settings.sidecarExtensions = [];
    const files = await app.importAttachments([imported('report', 'html'), imported('report.html', 'p7s')], null);
    expect(files.map((file) => file.path)).toEqual(['assets/random-1.html', 'assets/random-2.p7s']);
  });

  it('finds a separately imported signature by its base arrival name in the destination folder', async () => {
    const note = await app.vault.create('note.md', '');
    vi.spyOn(app.workspace, 'getActiveFile').mockReturnValue(note);
    await app.vault.create('assets/id.html', 'base');
    originalNames.set('assets/id.html', 'document.html');
    const file = await saver.saveAttachment({ attachmentFileBaseName: 'document.html', attachmentFileContent: new ArrayBuffer(1), attachmentFileExtension: 'p7s' });
    expect(file.path).toBe('assets/id.html.p7s');
    expect(showNotice).not.toHaveBeenCalled();
  });

  it('does not borrow a base from another destination folder', async () => {
    const note = await app.vault.create('note.md', '');
    vi.spyOn(app.workspace, 'getActiveFile').mockReturnValue(note);
    await app.vault.create('elsewhere.html', 'other base');
    const files = await app.importAttachments([imported('elsewhere.html', 'p7s')], null);
    expect(files[0]?.path).toBe('assets/elsewhere.html.p7s');
    expect(showNotice).toHaveBeenCalledOnce();
  });

  it('resolves duplicate arrival names within the destination folder', async () => {
    const note = await app.vault.create('note.md', '');
    vi.spyOn(app.workspace, 'getActiveFile').mockReturnValue(note);
    await app.vault.create('assets/id.html', 'base here');
    await app.vault.create('other.html', 'base elsewhere');
    originalNames.set('assets/id.html', 'document.html');
    originalNames.set('other.html', 'document.html');
    const files = await app.importAttachments([imported('document.html', 'p7s')], null);
    expect(files[0]?.path).toBe('assets/id.html.p7s');
    expect(showNotice).not.toHaveBeenCalled();
  });

  it('reports an orphan when an active note exists but no base does', async () => {
    const note = await app.vault.create('note.md', '');
    vi.spyOn(app.workspace, 'getActiveFile').mockReturnValue(note);
    const files = await app.importAttachments([imported('missing.html', 'p7s')], null);
    expect(files[0]?.name).toBe('missing.html.p7s');
    expect(showNotice).toHaveBeenCalledOnce();
  });

  it('leaves an occupied imported signature untouched', async () => {
    await app.vault.create('assets/random-1.html.p7s', 'existing signature');
    await expect(app.importAttachments([imported('report', 'html'), imported('report.html', 'p7s')], null)).rejects.toThrow('already exists');
    expect(await app.vault.adapter.read('assets/random-1.html.p7s')).toBe('existing signature');
    expect(save).toHaveBeenCalledTimes(1);
  });

  it('preserves signed base bytes even when image conversion is enabled', async () => {
    await app.importAttachments([imported('image', 'png'), imported('image.png', 'sig')], null);
    expect(save.mock.calls[0]?.[0].shouldPreserveContent).toBe(true);
    expect(save.mock.calls[1]?.[0].shouldPreserveContent).toBe(true);
  });

  it('does not independently collect a paired signature or an orphan', async () => {
    const base = await app.vault.create('assets/document.html', 'base');
    const signature = await app.vault.create('assets/document.html.p7s', 'sig');
    const orphan = await app.vault.create('assets/missing.sig', 'orphan');
    await app.vault.createFolder('assets/other');
    function params(file: TFile): Parameters<AttachmentPathManager['getProperAttachmentPath']>[0] {
      return strictProxy<Parameters<AttachmentPathManager['getProperAttachmentPath']>[0]>({ actionContext: ActionContext.CollectAttachments, attachmentFile: file });
    }
    expect(await pathManager.getProperAttachmentPath(params(signature))).toBeNull();
    expect(await pathManager.getProperAttachmentPath(params(base))).toBe('assets/independent.pdf');
    expect(await pathManager.getProperAttachmentPath(params(orphan))).toBeNull();
    expect(showNotice).toHaveBeenCalledWith(expect.stringContaining('missing.sig'));
    showNotice.mockClear();
    expect(await pathManager.getProperAttachmentPath({ ...params(orphan), actionContext: ActionContext.ReadApi })).toBeNull();
    expect(showNotice).not.toHaveBeenCalled();
    orphan.parent = null;
    expect(await pathManager.getProperAttachmentPath(params(orphan))).toBeNull();
  });

  it('moves chained signatures with their base', async () => {
    const base = await app.vault.create('assets/doc.html', 'base');
    await app.vault.create('assets/doc.html.p7s.asc', 'outer');
    await app.vault.create('assets/doc.html.p7s', 'inner');
    await app.vault.createFolder('assets/folder');
    await app.vault.rename(base, 'renamed.html');
    expect(app.vault.getFileByPath('renamed.html.p7s.asc')).not.toBeNull();
    expect(app.vault.getFileByPath('renamed.html.p7s')).not.toBeNull();
  });

  it('restores earlier companions when a later companion fails', async () => {
    const base = await app.vault.create('assets/doc.html', 'base');
    await app.vault.create('assets/doc.html.p7s', 'first');
    await app.vault.create('assets/doc.html.sig', 'second');
    const rename = app.fileManager.renameFile.bind(app.fileManager);
    vi.spyOn(app.fileManager, 'renameFile').mockImplementationOnce(rename).mockRejectedValueOnce(new Error('second move failed'));
    await expect(app.vault.rename(base, 'renamed.html')).rejects.toThrow('second move failed');
    expect(base.path).toBe('assets/doc.html');
    expect(await app.vault.adapter.read('assets/doc.html.p7s')).toBe('first');
    expect(await app.vault.adapter.read('assets/doc.html.sig')).toBe('second');
  });

  it('moves folders without independently renaming their contained companions', async () => {
    const folder = app.vault.getFolderByPath('assets');
    if (!folder) {
      throw new Error('Fixture folder missing');
    }
    await app.vault.create('assets/doc.html', 'base');
    await app.vault.create('assets/doc.html.p7s', 'sig');
    await app.vault.rename(folder, 'moved');
    expect(app.vault.getFileByPath('moved/doc.html.p7s')).not.toBeNull();
  });

  it('leaves a file without a parent alone when it has no companions', async () => {
    const file = await app.vault.create('assets/detached.html', 'base');
    file.parent = null;
    await app.vault.rename(file, 'detached.html');
    expect(file.path).toBe('detached.html');
  });

  it('shares a nested batch and forgets its entries after the operation', async () => {
    const attachment = imported('doc', 'html');
    const noData: ImportedAttachment = { data: null, extension: '', name: 'empty' };
    const first = await component.runImportBatch([attachment], async () => await app.importAttachments([noData, attachment, attachment], null));
    const second = await app.importAttachments([attachment], null);
    expect(first[0]?.path).toBe('assets/random-1.html');
    expect(first[1]).toBe(first[0]);
    expect(second[0]?.path).toBe('assets/random-2.html');
  });

  it('saves ordinary single attachments outside a batch', async () => {
    const file = await saver.saveAttachment({ attachmentFileBaseName: 'plain', attachmentFileContent: new ArrayBuffer(1), attachmentFileExtension: 'pdf' });
    expect(file.path).toBe('assets/random-1.pdf');
  });

  it('leaves companion rename plans to the base regardless of dependency plan order', async () => {
    const base = await app.vault.create('assets/doc.html', 'base');
    const signature = await app.vault.create('assets/doc.html.p7s', 'sig');
    function params(pathOrFile: string | TFile): Parameters<AttachmentPathManager['getAvailablePathForAttachments']>[0] {
      return strictProxy<Parameters<AttachmentPathManager['getAvailablePathForAttachments']>[0]>({ context: AttachmentPathContext.RenameNote, oldAttachmentPathOrFile: pathOrFile });
    }
    expect(await pathManager.getAvailablePathForAttachments(params(signature.path))).toBe('assets/doc.html.p7s');
    expect(await pathManager.getAvailablePathForAttachments(params(base))).toBe('assets/independent.pdf');
    expect(await pathManager.getAvailablePathForAttachments(params('missing.html'))).toBe('assets/independent.pdf');
    await app.vault.rename(base, 'renamed.html');
    expect(await pathManager.getAvailablePathForAttachments(params(signature))).toBe('renamed.html.p7s');
    signature.parent = null;
    expect(await pathManager.getAvailablePathForAttachments(params(signature))).toBe('renamed.html.p7s');
    const unknown = strictProxy<Parameters<AttachmentPathManager['getAvailablePathForAttachments']>[0]>({ context: AttachmentPathContext.Unknown });
    expect(await pathManager.getAvailablePathForAttachments(unknown)).toBe('assets/independent.pdf');
  });
});
