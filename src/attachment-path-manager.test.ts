import type {
  App,
  CachedMetadata,
  FileStats,
  Reference,
  ReferenceCache,
  TFile,
  Vault
} from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  AttachmentPathContext,
  DUMMY_PATH,
  getAvailablePathForAttachments
} from 'obsidian-dev-utils/obsidian/attachment-path';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import {
  getFileOrNull,
  getPath,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { extractLinkFile } from 'obsidian-dev-utils/obsidian/link';
import {
  getAllLinks,
  getCacheSafe
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { createFolderSafe } from 'obsidian-dev-utils/obsidian/vault';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';
import type { TokenValidator } from './token-validator.ts';

import { AttachmentPathManager } from './attachment-path-manager.ts';
import { translationsMap } from './i18n/locales/translations-map.ts';
import { IMPORT_FILES_PREFIX } from './patches/share-receiver-import-files-patch-component.ts';
import { Substitutions } from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';
import { TokenValidationMode } from './token-validator.ts';

const noticeInstances: unknown[] = [];

vi.mock('obsidian', async (importOriginal) => {
  const actual = await importOriginal<typeof import('obsidian')>();
  const ActualNotice = actual.Notice;
  class RecordingNotice extends ActualNotice {
    public constructor(message: DocumentFragment | string, duration?: number) {
      super(message, duration);
      noticeInstances.push(this);
    }
  }
  return {
    ...actual,
    Notice: RecordingNotice
  };
});

vi.mock('obsidian-dev-utils/obsidian/attachment-path', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/attachment-path')>(),
  getAvailablePathForAttachments: vi.fn<typeof getAvailablePathForAttachments>()
}));

vi.mock('obsidian-dev-utils/obsidian/file-system', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/file-system')>(),
  getFileOrNull: vi.fn<typeof getFileOrNull>(),
  getPath: vi.fn<typeof getPath>(),
  isNote: vi.fn<typeof isNote>()
}));

vi.mock('obsidian-dev-utils/obsidian/link', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/link')>(),
  extractLinkFile: vi.fn<typeof extractLinkFile>()
}));

vi.mock('obsidian-dev-utils/obsidian/metadata-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/metadata-cache')>(),
  getAllLinks: vi.fn<typeof getAllLinks>(),
  getCacheSafe: vi.fn<typeof getCacheSafe>()
}));

vi.mock('obsidian-dev-utils/obsidian/vault', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/vault')>(),
  createFolderSafe: vi.fn<typeof createFolderSafe>()
}));

const mockGetAvailablePathForAttachments = vi.mocked(getAvailablePathForAttachments);
const mockGetFileOrNull = vi.mocked(getFileOrNull);
const mockGetPath = vi.mocked(getPath);
const mockIsNote = vi.mocked(isNote);
const mockExtractLinkFile = vi.mocked(extractLinkFile);
const mockGetAllLinks = vi.mocked(getAllLinks);
const mockGetCacheSafe = vi.mocked(getCacheSafe);
const mockCreateFolderSafe = vi.mocked(createFolderSafe);

interface TestContext {
  create: ReturnType<typeof vi.fn<Vault['create']>>;
  exists: ReturnType<typeof vi.fn<Vault['exists']>>;
  getAvailablePath: ReturnType<typeof vi.fn<Vault['getAvailablePath']>>;
  getAvailablePathForAttachmentsOriginal: ReturnType<typeof vi.fn<Vault['getAvailablePathForAttachments']>>;
  isPathIgnored: ReturnType<typeof vi.fn<PluginSettings['isPathIgnored']>>;
  manager: AttachmentPathManager;
  pluginSettingsComponent: PluginSettingsComponent;
  readBinary: ReturnType<typeof vi.fn<Vault['readBinary']>>;
  settings: PluginSettings;
  tokenValidator: TokenValidator;
  validateFileName: ReturnType<typeof vi.fn<TokenValidator['validateFileName']>>;
  validatePath: ReturnType<typeof vi.fn<TokenValidator['validatePath']>>;
}

let ctx: TestContext;

function createManager(): TestContext {
  const isPathIgnored = vi.fn<PluginSettings['isPathIgnored']>().mockReturnValue(false);
  const settings = castTo<PluginSettings>({
    attachmentFolderPath: 'assets',
    collectedAttachmentFileName: '',
    emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
    generatedAttachmentFileName: 'generated',
    isPathIgnored,
    renamedAttachmentFileName: '',
    shouldRenameCollectedAttachments: false,
    specialCharacters: '',
    specialCharactersReplacement: '-'
  });

  const exists = vi.fn<Vault['exists']>().mockResolvedValue(true);
  const create = vi.fn<Vault['create']>();
  const readBinary = vi.fn<Vault['readBinary']>().mockResolvedValue(new ArrayBuffer(0));
  const getAvailablePath = vi.fn<Vault['getAvailablePath']>().mockImplementation((path, extension) => extension ? `${path}.${extension}` : path);
  const getAvailablePathForAttachmentsOriginal = vi.fn<Vault['getAvailablePathForAttachments']>().mockResolvedValue('original-path');

  const vault = strictProxy<Vault>({
    create,
    exists,
    getAvailablePath,
    readBinary
  });

  const app = strictProxy<App>({
    vault,
    workspace: strictProxy<App['workspace']>({ activeEditor: null })
  });

  const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
    replaceSpecialCharacters: (str: string) => settings.specialCharacters ? str.replaceAll(settings.specialCharacters, settings.specialCharactersReplacement) : str,
    settings
  });

  const validatePath = vi.fn<TokenValidator['validatePath']>().mockResolvedValue('');
  const validateFileName = vi.fn<TokenValidator['validateFileName']>().mockResolvedValue('');
  const tokenValidator = strictProxy<TokenValidator>({
    validateFileName,
    validatePath
  });

  const manager = new AttachmentPathManager({
    app,
    getAvailablePathForAttachmentsOriginal,
    pluginSettingsComponent,
    tokenValidator
  });

  return {
    create,
    exists,
    getAvailablePath,
    getAvailablePathForAttachmentsOriginal,
    isPathIgnored,
    manager,
    pluginSettingsComponent,
    readBinary,
    settings,
    tokenValidator,
    validateFileName,
    validatePath
  };
}

function createSubstitutions(actionContext: ActionContext): Substitutions {
  return new Substitutions({
    actionContext,
    app: strictProxy<App>({ workspace: strictProxy<App['workspace']>({ activeEditor: null }) }),
    noteFilePath: 'notes/note.md',
    originalAttachmentFileName: 'img.png',
    pluginSettingsComponent: ctx.pluginSettingsComponent,
    tokenValidator: ctx.tokenValidator
  });
}

function createTFile(overrides: Partial<TFile>): TFile {
  return strictProxy<TFile>(overrides);
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

beforeEach(() => {
  vi.clearAllMocks();
  noticeInstances.length = 0;
  mockGetFileOrNull.mockReturnValue(null);
  mockGetPath.mockImplementation((_app, pathOrFile) => typeof pathOrFile === 'string' ? pathOrFile : castTo<TFile>(pathOrFile).path);
  mockIsNote.mockReturnValue(true);
  mockGetAvailablePathForAttachments.mockResolvedValue('dev-utils-path');
  mockGetAllLinks.mockReturnValue([]);
  mockGetCacheSafe.mockResolvedValue(null);
  mockExtractLinkFile.mockReturnValue(null);
  mockCreateFolderSafe.mockResolvedValue(true);
  ctx = createManager();
});

describe('AttachmentPathManager', () => {
  describe('getAttachmentFolderFullPathForPath', () => {
    it('should resolve the attachment folder path for the note', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      const result = await ctx.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      });
      expect(result).toBe('assets');
    });

    it('should resolve a relative path against the note folder path', async () => {
      ctx.settings.attachmentFolderPath = './assets';
      const stat = strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 });
      const result = await ctx.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileContent: new ArrayBuffer(0),
        attachmentFileName: 'img.png',
        attachmentFileStats: stat,
        notePath: 'notes/note.md',
        oldNoteFilePath: 'old.md'
      });
      expect(result).toBe('notes/assets');
    });
  });

  describe('getGeneratedAttachmentFileBaseName', () => {
    it('should use the collected attachment file name template for CollectAttachments', async () => {
      ctx.settings.collectedAttachmentFileName = 'collected';
      const result = await ctx.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.CollectAttachments));
      expect(result).toBe('collected');
    });

    it('should use the renamed attachment file name template for RenameNote', async () => {
      ctx.settings.renamedAttachmentFileName = 'renamed';
      const result = await ctx.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.RenameNote));
      expect(result).toBe('renamed');
    });

    it('should fall back to the generated attachment file name template by default', async () => {
      ctx.settings.generatedAttachmentFileName = 'generated';
      const result = await ctx.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment));
      expect(result).toBe('generated');
    });

    it('should fall back to the generated template when the chosen template is empty', async () => {
      ctx.settings.collectedAttachmentFileName = '';
      ctx.settings.generatedAttachmentFileName = 'generated';
      const result = await ctx.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.CollectAttachments));
      expect(result).toBe('generated');
    });

    it('should validate the file name part of the resolved path', async () => {
      ctx.settings.generatedAttachmentFileName = 'folder/file';
      await ctx.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment));
      expect(ctx.validateFileName).toHaveBeenCalledWith(expect.objectContaining({
        fileName: 'file',
        tokenValidationMode: TokenValidationMode.Error
      }));
    });

    it('should throw and notify when the path validation fails', async () => {
      ctx.settings.generatedAttachmentFileName = 'bad';
      ctx.validatePath.mockResolvedValueOnce('').mockResolvedValue('invalid path');
      await expect(ctx.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment))).rejects.toThrow('is invalid');
      expect(noticeInstances.length).toBeGreaterThan(0);
    });

    it('should throw and notify when the file name validation fails', async () => {
      ctx.settings.generatedAttachmentFileName = 'bad';
      ctx.validateFileName.mockResolvedValue('invalid file name');
      await expect(ctx.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment))).rejects.toThrow('is invalid');
    });

    it('should use an empty file name when the resolved path is empty', async () => {
      ctx.settings.generatedAttachmentFileName = '';
      await ctx.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment));
      expect(ctx.validateFileName).toHaveBeenCalledWith(expect.objectContaining({ fileName: '' }));
    });
  });

  describe('resolvePathTemplate (via getAttachmentFolderFullPathForPath)', () => {
    it('should clean special characters and trailing dots from each path part', async () => {
      ctx.settings.specialCharacters = 'a';
      ctx.settings.specialCharactersReplacement = 'A';
      ctx.settings.attachmentFolderPath = 'a /b. ';
      const result = await ctx.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      });
      expect(result).toBe('A/b');
    });

    it('should preserve single and double dot path parts during cleaning', async () => {
      ctx.settings.attachmentFolderPath = './..';
      const result = await ctx.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'notes/note.md'
      });
      expect(result).toBe('');
    });

    it('should throw and notify when the resolved path validation fails', async () => {
      ctx.settings.attachmentFolderPath = 'bad';
      ctx.validatePath.mockResolvedValue('invalid');
      await expect(ctx.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      })).rejects.toThrow('is invalid');
      expect(noticeInstances.length).toBeGreaterThan(0);
    });

    it('should normalize an empty resolved path to an empty string', async () => {
      ctx.settings.attachmentFolderPath = '.';
      const result = await ctx.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      });
      expect(result).toBe('');
    });

    it('should throw when the resolved path is still relative after normalization', async () => {
      ctx.settings.attachmentFolderPath = '../outside';
      await expect(ctx.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      })).rejects.toThrow('should be absolute');
    });
  });

  describe('getSequenceNumber', () => {
    it('should return 0 when there is no old attachment file', async () => {
      mockGetFileOrNull.mockReturnValue(null);
      const result = await ctx.manager.getSequenceNumber('note.md', 'old.png');
      expect(result).toBe(0);
    });

    it('should return 0 when there is no cache for the note', async () => {
      mockGetFileOrNull.mockReturnValue(createTFile({ path: 'old.png' }));
      mockGetCacheSafe.mockResolvedValue(null);
      const result = await ctx.manager.getSequenceNumber('note.md', 'old.png');
      expect(result).toBe(0);
    });

    it('should return the 1-based index of the matching link', async () => {
      const oldFile = createTFile({ path: 'old.png' });
      const otherFile = createTFile({ path: 'other.png' });
      const link1 = strictProxy<Reference>({});
      const link2 = strictProxy<Reference>({});
      mockGetFileOrNull.mockReturnValue(oldFile);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadata>({}));
      mockGetAllLinks.mockReturnValue([link1, link2]);
      mockExtractLinkFile.mockImplementation((_app, link) => link === link2 ? oldFile : otherFile);
      const result = await ctx.manager.getSequenceNumber('note.md', 'old.png');
      expect(result).toBe(2);
    });

    it('should return 0 when no link matches the old attachment file', async () => {
      const oldFile = createTFile({ path: 'old.png' });
      mockGetFileOrNull.mockReturnValue(oldFile);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadata>({}));
      mockGetAllLinks.mockReturnValue([strictProxy<Reference>({})]);
      mockExtractLinkFile.mockReturnValue(createTFile({ path: 'other.png' }));
      const result = await ctx.manager.getSequenceNumber('note.md', 'old.png');
      expect(result).toBe(0);
    });
  });

  describe('getProperAttachmentPath', () => {
    it('should keep the original name when collected attachment renaming is disabled', async () => {
      ctx.settings.shouldRenameCollectedAttachments = false;
      ctx.settings.attachmentFolderPath = 'assets';
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'old/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await ctx.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: strictProxy<Reference>({})
      });
      expect(result).toBe('assets/img.png');
    });

    it('should generate a new name when collected attachment renaming is enabled', async () => {
      ctx.settings.shouldRenameCollectedAttachments = true;
      ctx.settings.collectedAttachmentFileName = 'collected';
      ctx.settings.attachmentFolderPath = 'assets';
      const referenceCache = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 3, offset: 0 } }
      });
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'old/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await ctx.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: referenceCache
      });
      expect(result).toBe('assets/collected.png');
    });

    it('should use cursor line 0 for a non-reference-cache reference', async () => {
      ctx.settings.shouldRenameCollectedAttachments = true;
      ctx.settings.collectedAttachmentFileName = 'collected';
      ctx.settings.attachmentFolderPath = 'assets';
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'old/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await ctx.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: castTo<Reference>({ link: 'x', original: 'x' })
      });
      expect(result).toBe('assets/collected.png');
    });

    it('should return null when the new path equals the current path', async () => {
      ctx.settings.shouldRenameCollectedAttachments = false;
      ctx.settings.attachmentFolderPath = 'assets';
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'assets/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await ctx.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: strictProxy<Reference>({})
      });
      expect(result).toBeNull();
    });
  });

  describe('getAvailablePathForAttachments', () => {
    it('should seed default content and stats for a dummy attachment base name', async () => {
      mockGetFileOrNull.mockReturnValue(null);
      mockIsNote.mockReturnValue(false);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: DUMMY_PATH,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: null,
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('dev-utils-path');
    });

    it('should read the attachment content lazily through the provider for a note path', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      mockIsNote.mockReturnValue(true);
      const content = new ArrayBuffer(8);
      const readAttachmentFileContent = vi.fn<() => Promise<ArrayBuffer>>().mockResolvedValue(content);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent,
        shouldSkipDuplicateCheck: true,
        shouldSkipGeneratedAttachmentFileName: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/img.png');
      expect(readAttachmentFileContent).toHaveBeenCalledOnce();
    });

    it('should seed empty content for a dummy attachment base name on a note path', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      mockIsNote.mockReturnValue(true);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: DUMMY_PATH,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipGeneratedAttachmentFileName: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe(`assets/${DUMMY_PATH}.png`);
    });

    it('should strip the import-files prefix and skip generated file name', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      mockIsNote.mockReturnValue(true);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/img.png');
    });

    it('should delegate to the original function when the note path is ignored', async () => {
      const noteFile = createTFile({ path: 'ignored/note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      ctx.isPathIgnored.mockReturnValue(true);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'ignored/note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('original-path');
      expect(ctx.getAvailablePathForAttachmentsOriginal).toHaveBeenCalledWith('img', 'png', noteFile);
    });

    it('should delegate to the dev-utils helper for a non-note path', async () => {
      mockGetFileOrNull.mockReturnValue(null);
      mockIsNote.mockReturnValue(false);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.txt',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: false
      });
      expect(result).toBe('dev-utils-path');
      expect(mockGetAvailablePathForAttachments).toHaveBeenCalledWith(expect.objectContaining({
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: false
      }));
    });

    it('should apply default skip flags for a non-note path', async () => {
      mockGetFileOrNull.mockReturnValue(null);
      mockIsNote.mockReturnValue(false);
      await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.txt',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipMissingAttachmentFolderCreation: undefined
      });
      expect(mockGetAvailablePathForAttachments).toHaveBeenCalledWith(expect.objectContaining({
        shouldSkipDuplicateCheck: false,
        shouldSkipMissingAttachmentFolderCreation: true
      }));
    });

    it('should generate the attachment file name for a note path', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      ctx.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/generated.png');
    });

    it('should use the duplicate-checked available path when duplicate check is not skipped', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: false,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(ctx.getAvailablePath).toHaveBeenCalledWith('assets/img', 'png');
      expect(result).toBe('assets/img.png');
    });

    it('should use the duplicate-checked available path with an empty extension', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: '',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: false,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(ctx.getAvailablePath).toHaveBeenCalledWith('assets/img', '');
    });

    it('should create the missing attachment folder when folder creation is not skipped', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      ctx.settings.emptyFolderBehavior = EmptyFolderBehavior.DeleteWithEmptyParents;
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      ctx.exists.mockResolvedValue(false);
      await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: false
      });
      expect(mockCreateFolderSafe).toHaveBeenCalledWith(expect.anything(), 'assets');
      expect(ctx.create).not.toHaveBeenCalled();
    });

    it('should create a gitkeep file when the empty folder behavior is Keep', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      ctx.settings.emptyFolderBehavior = EmptyFolderBehavior.Keep;
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      ctx.exists.mockResolvedValue(false);
      await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: false
      });
      expect(ctx.create).toHaveBeenCalledWith('assets/.gitkeep', '');
    });

    it('should not create the folder when it already exists', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      ctx.exists.mockResolvedValue(true);
      await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: false
      });
      expect(mockCreateFolderSafe).not.toHaveBeenCalled();
    });

    it('should resolve the cursor line and sequence number from the note cache when generating a name', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      ctx.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const link = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 2, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadata>({}));
      mockGetAllLinks.mockReturnValue([link]);
      mockExtractLinkFile.mockReturnValue(oldFile);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/generated.png');
      expect(mockGetAllLinks).toHaveBeenCalled();
    });
  });

  describe('getCursorLine (via getAvailablePathForAttachments)', () => {
    it('should skip non-reference-cache links and links with no resolved file', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      ctx.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const otherFile = createTFile({ path: 'other.png' });
      const nonReferenceCacheLink = castTo<Reference>({ link: 'x', original: 'x' });
      const unresolvedReferenceCacheLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 1, offset: 0 } }
      });
      const nonMatchingReferenceCacheLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 4, offset: 0 } }
      });
      const matchingReferenceCacheLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 5, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadata>({}));
      mockGetAllLinks.mockReturnValue([nonReferenceCacheLink, unresolvedReferenceCacheLink, nonMatchingReferenceCacheLink, matchingReferenceCacheLink]);
      mockExtractLinkFile.mockReturnValueOnce(null).mockReturnValueOnce(otherFile).mockReturnValue(oldFile);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/generated.png');
    });

    it('should resolve the old note file path and a matching cursor line', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      ctx.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const referenceCacheLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 7, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadata>({}));
      mockGetAllLinks.mockReturnValue([referenceCacheLink]);
      mockExtractLinkFile.mockReturnValue(oldFile);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        oldNotePathOrFile: 'old-note.md',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/generated.png');
      expect(mockGetPath).toHaveBeenCalledWith(expect.anything(), 'old-note.md');
    });

    it('should return cursor line 0 when no link matches the old attachment file', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      ctx.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const otherFile = createTFile({ path: 'other.png' });
      const referenceCacheLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 6, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadata>({}));
      mockGetAllLinks.mockReturnValue([referenceCacheLink]);
      mockExtractLinkFile.mockReturnValue(otherFile);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/generated.png');
      expect(mockExtractLinkFile).toHaveBeenCalled();
    });

    it('should return cursor line 0 when no cache exists for the note', async () => {
      ctx.settings.attachmentFolderPath = 'assets';
      ctx.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(null);
      const result = await ctx.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/generated.png');
    });
  });
});
