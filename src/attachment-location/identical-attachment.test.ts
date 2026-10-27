import type { FileChange } from '@mnaoumov/obsidian-lib/file-change';
import type {
  CanvasReference,
  CanvasTextNodeReference
} from '@mnaoumov/obsidian-lib/reference';
import type { CustomArrayDict } from '@obsidian-typings/obsidian-public-latest';
import type {
  Reference,
  TFile
} from 'obsidian';

import { getCanvasReferences } from '@mnaoumov/obsidian-lib/canvas';
import { applyFileChanges } from '@mnaoumov/obsidian-lib/file-change';
import {
  editLinks,
  extractLinkFile,
  updateLink
} from '@mnaoumov/obsidian-lib/link';
import { getBacklinksForFileSafe } from '@mnaoumov/obsidian-lib/metadata-cache';
import { printError } from '@mnaoumov/typescript-lib/error';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';

import { PluginSettings } from '../settings/plugin-settings.ts';
import {
  findIdenticalAttachmentFile,
  mergeIntoIdenticalAttachment
} from './identical-attachment.ts';

vi.mock('@mnaoumov/typescript-lib/error', () => ({
  printError: vi.fn<(error: unknown) => void>()
}));

// The mock App models no link index, so the link and backlink plumbing is driven directly.
vi.mock('@mnaoumov/obsidian-lib/canvas', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/canvas')>(),
  getCanvasReferences: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/file-change', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/file-change')>(),
  applyFileChanges: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/link', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/link')>(),
  editLinks: vi.fn(),
  extractLinkFile: vi.fn(),
  updateLink: vi.fn()
}));

vi.mock('@mnaoumov/obsidian-lib/metadata-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/metadata-cache')>(),
  getBacklinksForFileSafe: vi.fn()
}));

const mockApplyFileChanges = vi.mocked(applyFileChanges);
const mockEditLinks = vi.mocked(editLinks);
const mockExtractLinkFile = vi.mocked(extractLinkFile);
const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);
const mockGetCanvasReferences = vi.mocked(getCanvasReferences);
const mockUpdateLink = vi.mocked(updateLink);

const ATTACHMENT_PATH = 'inbox/image.png';
const DESTINATION_PATH = 'assets/image.png';

describe('identical-attachment', () => {
  let app: App;
  let settings: PluginSettings;
  let pluginSettingsComponent: PluginSettingsComponent;

  beforeEach(async () => {
    app = App.createConfigured__();
    settings = new PluginSettings();
    settings.shouldDeduplicateIdenticalAttachments = true;
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({ settings });
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    // Obsidian always carries a link format; the mock models none, and link generation refuses an unknown one.
    getApp().vault.setConfig('newLinkFormat', 'shortest');
    // Shortest-form link generation asks which files share the name; the mock models no such lookup.
    // eslint-disable-next-line unicorn/name-replacements -- `getLinkpathDest` is Obsidian's own spelling; the stub has to answer to it.
    getApp().metadataCache.getLinkpathDest = (linkpath: string): TFile[] => getApp().vault.getFiles().filter((file) => file.name === linkpath || file.basename === linkpath);
    await getApp().vault.createFolder('inbox');
    await getApp().vault.createFolder('assets');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function bytes(...values: number[]): ArrayBuffer {
    return new Uint8Array(values).buffer;
  }

  function find(attachmentFile: TFile, destinationPath = DESTINATION_PATH): Promise<null | TFile> {
    return findIdenticalAttachmentFile({
      app: getApp(),
      attachmentPathOrFile: attachmentFile,
      destinationPath,
      pluginSettingsComponent
    });
  }

  function getApp(): ReturnType<App['asOriginalType__']> {
    return app.asOriginalType__();
  }

  describe('findIdenticalAttachmentFile', () => {
    it('should find a destination holding the same bytes', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      const occupant = await getApp().vault.createBinary(DESTINATION_PATH, bytes(1, 2, 3));

      expect(await find(attachmentFile)).toBe(occupant);
    });

    it('should find it whatever the case of the destination path, as the suffix would', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      const occupant = await getApp().vault.createBinary('assets/Image.png', bytes(1, 2, 3));

      expect(await find(attachmentFile)).toBe(occupant);
    });

    it('should not match a destination holding different bytes of the same size', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      await getApp().vault.createBinary(DESTINATION_PATH, bytes(1, 2, 4));

      expect(await find(attachmentFile)).toBeNull();
    });

    it('should not read either file when the sizes differ', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      await getApp().vault.createBinary(DESTINATION_PATH, bytes(1, 2));
      const readBinarySpy = vi.spyOn(getApp().vault, 'readBinary');

      expect(await find(attachmentFile)).toBeNull();
      expect(readBinarySpy).not.toHaveBeenCalled();
    });

    it('should not match when the bytes read are longer than the stats said, as after a write the stats missed', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      const occupant = await getApp().vault.createBinary(DESTINATION_PATH, bytes(1, 2, 3));
      const readBinary = getApp().vault.readBinary.bind(getApp().vault);
      vi.spyOn(getApp().vault, 'readBinary').mockImplementation((file) => file === occupant ? Promise.resolve(bytes(1, 2, 3, 4)) : readBinary(file));

      expect(await find(attachmentFile)).toBeNull();
    });

    it('should not match when the setting is off', async () => {
      settings.shouldDeduplicateIdenticalAttachments = false;
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      await getApp().vault.createBinary(DESTINATION_PATH, bytes(1, 2, 3));

      expect(await find(attachmentFile)).toBeNull();
    });

    it('should not match a free destination', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));

      expect(await find(attachmentFile)).toBeNull();
    });

    it('should not match a destination holding a folder', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      await getApp().vault.createFolder(DESTINATION_PATH);

      expect(await find(attachmentFile)).toBeNull();
    });

    it('should not match the attachment itself', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));

      expect(await find(attachmentFile, ATTACHMENT_PATH)).toBeNull();
    });

    it('should not match an attachment that does not exist', async () => {
      await getApp().vault.createBinary(DESTINATION_PATH, bytes(1, 2, 3));

      expect(
        await findIdenticalAttachmentFile({
          app: getApp(),
          attachmentPathOrFile: ATTACHMENT_PATH,
          destinationPath: DESTINATION_PATH,
          pluginSettingsComponent
        })
      ).toBeNull();
    });

    it('should keep both files when a read fails', async () => {
      const attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      await getApp().vault.createBinary(DESTINATION_PATH, bytes(1, 2, 3));
      const error = new Error('read failed');
      vi.spyOn(getApp().vault, 'readBinary').mockRejectedValue(error);

      expect(await find(attachmentFile)).toBeNull();
      expect(printError).toHaveBeenCalledWith(error);
    });
  });

  describe('mergeIntoIdenticalAttachment', () => {
    let attachmentFile: TFile;
    let identicalFile: TFile;

    beforeEach(async () => {
      attachmentFile = await getApp().vault.createBinary(ATTACHMENT_PATH, bytes(1, 2, 3));
      identicalFile = await getApp().vault.createBinary(DESTINATION_PATH, bytes(1, 2, 3));
      mockEditLinks.mockResolvedValue();
      mockApplyFileChanges.mockResolvedValue();
      mockGetCanvasReferences.mockResolvedValue([]);
      mockUpdateLink.mockReturnValue('![[assets/image.png]]');
      mockExtractLinkFile.mockImplementation(({ link }) => link.link === ATTACHMENT_PATH ? attachmentFile : null);
    });

    function merge(skippedCanvasPaths?: ReadonlySet<string>): Promise<void> {
      return mergeIntoIdenticalAttachment({
        app: getApp(),
        attachmentFile,
        identicalFile,
        pluginNoticeComponent: null,
        resourceLockComponent: null,
        ...skippedCanvasPaths && { skippedCanvasPaths }
      });
    }

    function mockBacklinks(...notePathsPerCall: string[][]): void {
      for (const notePaths of notePathsPerCall) {
        mockGetBacklinksForFileSafe.mockResolvedValueOnce(strictProxy<CustomArrayDict<Reference>>({ keys: () => notePaths }));
      }
    }

    function reference(link: string): Reference {
      return strictProxy<Reference>({ link, original: `![[${link}]]` });
    }

    it('should repoint every note linking to the attachment, then trash it', async () => {
      const note = await getApp().vault.create('note.md', '');
      mockBacklinks(['note.md'], []);
      const trashFileSpy = vi.spyOn(getApp().fileManager, 'trashFile');

      await merge();

      expect(mockEditLinks).toHaveBeenCalledOnce();
      const { linkConverter, pathOrFile } = ensureNonNullable(mockEditLinks.mock.calls[0])[0];
      expect(pathOrFile).toBe(note);
      expect(await linkConverter(reference(ATTACHMENT_PATH))).toBe('![[assets/image.png]]');
      expect(mockUpdateLink).toHaveBeenCalledWith(expect.objectContaining({
        newSourcePathOrFile: note,
        newTargetPathOrFile: identicalFile,
        oldTargetPathOrFile: attachmentFile
      }));
      expect(await linkConverter(reference('other.png'))).toBeUndefined();
      expect(trashFileSpy).toHaveBeenCalledExactlyOnceWith(attachmentFile);
      expect(getApp().vault.getFileByPath(DESTINATION_PATH)).toBe(identicalFile);
    });

    it('should skip a backlink that no longer resolves, and a canvas backlink, which is scanned instead', async () => {
      await getApp().vault.create('board.canvas', '{}');
      mockBacklinks(['gone.md', 'board.canvas'], []);

      await merge();

      expect(mockEditLinks).not.toHaveBeenCalled();
      expect(mockGetCanvasReferences).toHaveBeenCalledExactlyOnceWith(getApp(), getApp().vault.getFileByPath('board.canvas'));
    });

    it('should repoint a canvas file node at the identical path and regenerate a text-node embed', async () => {
      const canvasFile = await getApp().vault.create('board.canvas', '{}');
      mockBacklinks([], []);
      const fileNodeReference = castTo<CanvasReference>({ isCanvas: true, key: 'nodes.0.file', link: ATTACHMENT_PATH, original: ATTACHMENT_PATH });
      const textNodeReference = castTo<CanvasTextNodeReference>({
        isCanvas: true,
        key: 'nodes.1.text',
        link: ATTACHMENT_PATH,
        original: `![[${ATTACHMENT_PATH}]]`,
        originalReference: reference(ATTACHMENT_PATH),
        type: 'text'
      });
      const unrelatedReference = castTo<CanvasReference>({ isCanvas: true, key: 'nodes.2.file', link: 'other.png', original: 'other.png' });
      mockGetCanvasReferences.mockResolvedValue([fileNodeReference, textNodeReference, unrelatedReference]);

      await merge();

      expect(mockApplyFileChanges).toHaveBeenCalledOnce();
      const { changesProvider, pathOrFile } = ensureNonNullable(mockApplyFileChanges.mock.calls[0])[0];
      expect(pathOrFile).toBe(canvasFile);
      expect(castTo<FileChange[]>(changesProvider).map((change) => change.newContent)).toEqual([DESTINATION_PATH, '![[assets/image.png]]']);
    });

    it('should leave a canvas the caller rewrites itself alone', async () => {
      await getApp().vault.create('board.canvas', '{}');
      mockBacklinks([], []);

      await merge(new Set(['board.canvas']));

      expect(mockGetCanvasReferences).not.toHaveBeenCalled();
    });

    it('should not write a canvas that holds no reference to the attachment', async () => {
      await getApp().vault.create('board.canvas', '{}');
      mockBacklinks([], []);

      await merge();

      expect(mockApplyFileChanges).not.toHaveBeenCalled();
    });

    it('should keep the attachment when a reference to it survived the rewrite', async () => {
      await getApp().vault.create('note.md', '');
      mockBacklinks(['note.md'], ['note.md']);
      const trashFileSpy = vi.spyOn(getApp().fileManager, 'trashFile');

      await merge();

      expect(trashFileSpy).not.toHaveBeenCalled();
      expect(console.warn).toHaveBeenCalledWith(`Keeping attachment ${ATTACHMENT_PATH}, identical to ${DESTINATION_PATH}, as it is still referenced by:\n- note.md`);
    });

    it('should not count a canvas as a surviving reference, since Obsidian re-indexes a rewritten canvas lazily', async () => {
      mockBacklinks([], ['board.canvas', 'other.canvas']);
      const trashFileSpy = vi.spyOn(getApp().fileManager, 'trashFile');

      await merge(new Set(['board.canvas']));

      expect(trashFileSpy).toHaveBeenCalledExactlyOnceWith(attachmentFile);
    });
  });
});
