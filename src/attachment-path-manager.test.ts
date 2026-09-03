import type {
  App,
  FileStats,
  HeadingCache,
  Reference,
  ReferenceCache,
  TFile,
  Vault
} from 'obsidian';
import type { CachedMetadataEx } from 'obsidian-dev-utils/obsidian/metadata-cache';

import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  AttachmentPathContext,
  DUMMY_PATH,
  getAvailablePathForAttachments
} from 'obsidian-dev-utils/obsidian/attachment-path';
import { PluginNoticeComponent } from 'obsidian-dev-utils/obsidian/components/plugin-notice-component';
import {
  getFileOrNull,
  getPath,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { extractLinkFile } from 'obsidian-dev-utils/obsidian/link';
import {
  getCacheSafe,
  getLinks
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import {
  createFolderSafe,
  CreateFolderSafeResult,
  EmptyFolderBehavior
} from 'obsidian-dev-utils/obsidian/vault';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { HandedOverSettings } from './advanced-rename-and-delete-handler.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { PluginSettings } from './plugin-settings.ts';
import type { TokenValidator } from './token-validator.ts';

import { AttachmentPathManager } from './attachment-path-manager.ts';
import { translationsMap } from './i18n/locales/translations-map.ts';
import { IMPORT_FILES_PREFIX } from './patches/share-receiver-import-files-patch-component.ts';
import { promptWithPreview } from './prompt-with-preview-modal.ts';
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
  getCacheSafe: vi.fn<typeof getCacheSafe>(),
  getLinks: vi.fn<typeof getLinks>()
}));

vi.mock('obsidian-dev-utils/obsidian/vault', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/vault')>(),
  createFolderSafe: vi.fn<typeof createFolderSafe>()
}));

vi.mock('./prompt-with-preview-modal.ts', async (importOriginal) => ({
  ...await importOriginal<typeof import('./prompt-with-preview-modal.ts')>(),
  promptWithPreview: vi.fn<typeof promptWithPreview>()
}));

const mockGetAvailablePathForAttachments = vi.mocked(getAvailablePathForAttachments);
const mockGetFileOrNull = vi.mocked(getFileOrNull);
const mockGetPath = vi.mocked(getPath);
const mockIsNote = vi.mocked(isNote);
const mockExtractLinkFile = vi.mocked(extractLinkFile);
const mockGetLinks = vi.mocked(getLinks);
const mockGetCacheSafe = vi.mocked(getCacheSafe);
const mockCreateFolderSafe = vi.mocked(createFolderSafe);
const mockPromptWithPreview = vi.mocked(promptWithPreview);

// The handed-over settings live in Advanced Rename and Delete Handler since 12.0.0. Mutable here so a test
// Can still change one mid-run, exactly as it used to change .
interface MutableHandedOverSettings {
  emptyFolderBehavior: EmptyFolderBehavior;
  notePriorities: readonly string[];
  shouldRenameAttachmentFiles: boolean;
  treatAsAttachmentExtensions: readonly string[];
}

interface TestContext {
  create: ReturnType<typeof vi.fn<Vault['create']>>;
  exists: ReturnType<typeof vi.fn<Vault['exists']>>;
  getAvailablePath: ReturnType<typeof vi.fn<Vault['getAvailablePath']>>;
  getAvailablePathForAttachmentsOriginal: ReturnType<typeof vi.fn<Vault['getAvailablePathForAttachments']>>;
  handedOverSettings: MutableHandedOverSettings;
  isNoteEx: ReturnType<typeof vi.fn<PluginSettingsComponent['isNoteEx']>>;
  isPathIgnored: ReturnType<typeof vi.fn<HandedOverSettingsComponent['isPathIgnored']>>;
  manager: AttachmentPathManager;
  pluginSettingsComponent: PluginSettingsComponent;
  readBinary: ReturnType<typeof vi.fn<Vault['readBinary']>>;
  settings: PluginSettings;
  tokenValidator: TokenValidator;
  validateFileName: ReturnType<typeof vi.fn<TokenValidator['validateFileName']>>;
  validatePath: ReturnType<typeof vi.fn<TokenValidator['validatePath']>>;
}

let context: TestContext;

function createManager(): TestContext {
  const isPathIgnored = vi.fn<HandedOverSettingsComponent['isPathIgnored']>().mockReturnValue(false);
  const handedOverSettings: MutableHandedOverSettings = {
    emptyFolderBehavior: EmptyFolderBehavior.DeleteWithEmptyParents,
    notePriorities: [],
    shouldRenameAttachmentFiles: false,
    treatAsAttachmentExtensions: ['.excalidraw.md']
  };
  const handedOverSettingsComponent = strictProxy<HandedOverSettingsComponent>({
    isPathIgnored,
    settings: castTo<HandedOverSettings>(handedOverSettings)
  });
  const settings = castTo<PluginSettings>({
    attachmentFolderPath: 'assets',
    collectedAttachmentFileName: '',
    generatedAttachmentFileName: 'generated',
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

  const isNoteEx = vi.fn<PluginSettingsComponent['isNoteEx']>().mockReturnValue(false);
  const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
    isNoteEx,
    replaceSpecialCharacters: ($string: string) => settings.specialCharacters ? $string.replaceAll(settings.specialCharacters, () => settings.specialCharactersReplacement) : $string,
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
    handedOverSettingsComponent,
    pluginNoticeComponent: new PluginNoticeComponent({ app, pluginName: 'Custom Attachment Location' }),
    pluginSettingsComponent,
    tokenValidator
  });

  return {
    create,
    exists,
    getAvailablePath,
    getAvailablePathForAttachmentsOriginal,
    handedOverSettings,
    isNoteEx,
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
    pluginSettingsComponent: context.pluginSettingsComponent,
    tokenValidator: context.tokenValidator
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
  mockGetLinks.mockReturnValue([]);
  mockGetCacheSafe.mockResolvedValue(null);
  mockExtractLinkFile.mockReturnValue(null);
  mockCreateFolderSafe.mockResolvedValue(CreateFolderSafeResult.Created);
  mockPromptWithPreview.mockResolvedValue('prompted');
  context = createManager();
});

describe('AttachmentPathManager', () => {
  describe('getAttachmentFolderFullPathForPath', () => {
    it('should resolve the attachment folder path for the note', async () => {
      context.settings.attachmentFolderPath = 'assets';
      const result = await context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      });
      expect(result).toBe('assets');
    });

    it('should resolve a relative path against the note folder path', async () => {
      context.settings.attachmentFolderPath = './assets';
      const stat = strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 });
      const result = await context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
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
      context.settings.collectedAttachmentFileName = 'collected';
      const result = await context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.CollectAttachments));
      expect(result).toBe('collected');
    });

    it('should use the renamed attachment file name template for RenameNote', async () => {
      context.settings.renamedAttachmentFileName = 'renamed';
      const result = await context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.RenameNote));
      expect(result).toBe('renamed');
    });

    it('should fall back to the generated attachment file name template by default', async () => {
      context.settings.generatedAttachmentFileName = 'generated';
      const result = await context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment));
      expect(result).toBe('generated');
    });

    it('should keep the original file name when the collected template is empty', async () => {
      context.settings.collectedAttachmentFileName = '';
      context.settings.generatedAttachmentFileName = 'generated';
      const result = await context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.CollectAttachments));
      expect(result).toBe('img');
    });

    it('should keep the original file name when the renamed template is empty', async () => {
      context.settings.renamedAttachmentFileName = '';
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      context.settings.generatedAttachmentFileName = '${prompt}';
      const result = await context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.RenameNote));
      expect(result).toBe('img');
      expect(mockPromptWithPreview).not.toHaveBeenCalled();
    });

    it('should validate the file name part of the resolved path', async () => {
      context.settings.generatedAttachmentFileName = 'folder/file';
      await context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment));
      expect(context.validateFileName).toHaveBeenCalledWith(expect.objectContaining({
        fileName: 'file',
        tokenValidationMode: TokenValidationMode.Error
      }));
    });

    it('should throw and notify when the path validation fails', async () => {
      context.settings.generatedAttachmentFileName = 'bad';
      context.validatePath.mockResolvedValueOnce('').mockResolvedValue('invalid path');
      await expect(context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment))).rejects.toThrow('is invalid');
      expect(noticeInstances.length).toBeGreaterThan(0);
    });

    it('should throw and notify when the file name validation fails', async () => {
      context.settings.generatedAttachmentFileName = 'bad';
      context.validateFileName.mockResolvedValue('invalid file name');
      await expect(context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment))).rejects.toThrow('is invalid');
    });

    it('should use an empty file name when the resolved path is empty', async () => {
      context.settings.generatedAttachmentFileName = '';
      await context.manager.getGeneratedAttachmentFileBaseName(createSubstitutions(ActionContext.SaveAttachment));
      expect(context.validateFileName).toHaveBeenCalledWith(expect.objectContaining({ fileName: '' }));
    });
  });

  describe('resolvePathTemplate (via getAttachmentFolderFullPathForPath)', () => {
    it('should clean special characters and trailing dots from each path part', async () => {
      context.settings.specialCharacters = 'a';
      context.settings.specialCharactersReplacement = 'A';
      context.settings.attachmentFolderPath = 'a /b. ';
      const result = await context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      });
      expect(result).toBe('A/b');
    });

    it('should preserve single and double dot path parts during cleaning', async () => {
      context.settings.attachmentFolderPath = './..';
      const result = await context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'notes/note.md'
      });
      expect(result).toBe('');
    });

    it('should throw and notify when the resolved path validation fails', async () => {
      context.settings.attachmentFolderPath = 'bad';
      context.validatePath.mockResolvedValue('invalid');
      await expect(context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      })).rejects.toThrow('is invalid');
      expect(noticeInstances.length).toBeGreaterThan(0);
    });

    it('should normalize an empty resolved path to an empty string', async () => {
      context.settings.attachmentFolderPath = '.';
      const result = await context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      });
      expect(result).toBe('');
    });

    it('should throw when the resolved path is still relative after normalization', async () => {
      context.settings.attachmentFolderPath = '../outside';
      await expect(context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileName: 'img.png',
        notePath: 'note.md'
      })).rejects.toThrow('should be absolute');
    });
  });

  describe('getSequenceNumberMap', () => {
    it('should return an empty map when there is no cache for the note', async () => {
      mockGetCacheSafe.mockResolvedValue(null);
      const result = await context.manager.getSequenceNumberMap('note.md');
      expect(result.size).toBe(0);
    });

    it('should number distinct attachments and keep the first occurrence of a duplicate', async () => {
      const fileA = createTFile({ path: 'a.png' });
      const fileB = createTFile({ path: 'b.png' });
      const linkA1 = strictProxy<Reference>({});
      const linkA2 = strictProxy<Reference>({});
      const linkB = strictProxy<Reference>({});
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([linkA1, linkA2, linkB]);
      mockExtractLinkFile.mockImplementation(({ link }) => link === linkB ? fileB : fileA);
      const result = await context.manager.getSequenceNumberMap('note.md');
      // `a.png` keeps its first-occurrence number (1); its repeat still advances the slot, so `b.png` is 3.
      expect(result.get('a.png')).toBe(1);
      expect(result.get('b.png')).toBe(3);
    });

    it('should not advance the sequence number for note links (e.g. section embeds)', async () => {
      const attachmentFile = createTFile({ path: 'old.png' });
      const noteFile = createTFile({ path: 'other-note.md' });
      const sectionEmbedLink = strictProxy<Reference>({});
      const attachmentLink = strictProxy<Reference>({});
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([sectionEmbedLink, attachmentLink]);
      mockExtractLinkFile.mockImplementation(({ link }) => link === sectionEmbedLink ? noteFile : attachmentFile);
      context.isNoteEx.mockImplementation((pathOrFile) => pathOrFile === noteFile);
      const result = await context.manager.getSequenceNumberMap('note.md');
      // The section embed is skipped and must not advance the slot, so the attachment stays at 1.
      expect(result.get('old.png')).toBe(1);
    });

    it('should still count unresolvable links as attachment slots', async () => {
      // A broken attachment link (e.g. `![[missing.png]]`) still occupies a slot.
      // Following attachments then stay numbered by document position rather than jumping backwards.
      const attachmentFile = createTFile({ path: 'old.png' });
      const unresolvableLink = strictProxy<Reference>({});
      const attachmentLink = strictProxy<Reference>({});
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([unresolvableLink, attachmentLink]);
      mockExtractLinkFile.mockImplementation(({ link }) => link === attachmentLink ? attachmentFile : null);
      const result = await context.manager.getSequenceNumberMap('note.md');
      // The broken link still occupies slot 1, so the resolved attachment is numbered 2.
      expect(result.get('old.png')).toBe(2);
    });
  });

  describe('getDownloadedImagePath', () => {
    it('should resolve the downloaded image path without creating an existing folder', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
      context.exists.mockResolvedValue(true);
      const result = await context.manager.getDownloadedImagePath({
        actionContext: ActionContext.SaveAttachment,
        downloadedContent: new ArrayBuffer(4),
        fileExtension: 'png',
        fileName: 'my-image',
        noteFilePath: 'notes/note.md'
      });
      expect(result).toBe('assets/generated.png');
      expect(mockCreateFolderSafe).not.toHaveBeenCalled();
    });

    it('should create the target folder when it does not exist', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
      context.exists.mockResolvedValue(false);
      const result = await context.manager.getDownloadedImagePath({
        actionContext: ActionContext.SaveAttachment,
        downloadedContent: new ArrayBuffer(4),
        fileExtension: 'png',
        fileName: 'my-image',
        noteFilePath: 'notes/note.md'
      });
      expect(result).toBe('assets/generated.png');
      expect(mockCreateFolderSafe).toHaveBeenCalledWith(expect.anything(), 'assets');
    });

    it('should resolve the downloaded image path when no file extension is provided', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
      const result = await context.manager.getDownloadedImagePath({
        actionContext: ActionContext.SaveAttachment,
        downloadedContent: new ArrayBuffer(4),
        fileExtension: '',
        fileName: 'my-image',
        noteFilePath: 'notes/note.md'
      });
      expect(result).toBe('assets/generated');
    });
  });

  describe('getProperAttachmentPath', () => {
    it('should keep the original name when collected attachment renaming is disabled', async () => {
      context.settings.shouldRenameCollectedAttachments = false;
      context.settings.attachmentFolderPath = 'assets';
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'old/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await context.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: strictProxy<Reference>({}),
        sequenceNumber: 0
      });
      expect(result).toBe('assets/img.png');
    });

    it('should generate a new name when collected attachment renaming is enabled', async () => {
      context.settings.shouldRenameCollectedAttachments = true;
      context.settings.collectedAttachmentFileName = 'collected';
      context.settings.attachmentFolderPath = 'assets';
      const referenceCache = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 3, offset: 0 } }
      });
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'old/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await context.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: referenceCache,
        sequenceNumber: 0
      });
      expect(result).toBe('assets/collected.png');
    });

    it('should use the injected sequence number in the generated name', async () => {
      context.settings.shouldRenameCollectedAttachments = true;
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      context.settings.collectedAttachmentFileName = 'collected-${sequenceNumber:{length:2}}';
      context.settings.attachmentFolderPath = 'assets';
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'old/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await context.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: castTo<Reference>({ link: 'x', original: 'x' }),
        sequenceNumber: 7
      });
      expect(result).toBe('assets/collected-07.png');
    });

    it('should use cursor line 0 for a non-reference-cache reference', async () => {
      context.settings.shouldRenameCollectedAttachments = true;
      context.settings.collectedAttachmentFileName = 'collected';
      context.settings.attachmentFolderPath = 'assets';
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'old/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await context.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: castTo<Reference>({ link: 'x', original: 'x' }),
        sequenceNumber: 0
      });
      expect(result).toBe('assets/collected.png');
    });

    it('should return null when the new path equals the current path', async () => {
      context.settings.shouldRenameCollectedAttachments = false;
      context.settings.attachmentFolderPath = 'assets';
      const attachmentFile = createTFile({
        extension: 'png',
        name: 'img.png',
        path: 'assets/img.png',
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
      const result = await context.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: strictProxy<Reference>({}),
        sequenceNumber: 0
      });
      expect(result).toBeNull();
    });
  });

  describe('getAvailablePathForAttachments', () => {
    it('should seed default content and stats for a dummy attachment base name', async () => {
      mockGetFileOrNull.mockReturnValue(null);
      mockIsNote.mockReturnValue(false);
      const result = await context.manager.getAvailablePathForAttachments({
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

    it('should not read the attachment content when no token needs it', async () => {
      context.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      mockIsNote.mockReturnValue(true);
      const readAttachmentFileContent = vi.fn<() => Promise<ArrayBuffer>>().mockResolvedValue(new ArrayBuffer(8));
      const result = await context.manager.getAvailablePathForAttachments({
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
      expect(readAttachmentFileContent).not.toHaveBeenCalled();
    });

    it('should seed empty content for a dummy attachment base name on a note path', async () => {
      context.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      mockIsNote.mockReturnValue(true);
      const result = await context.manager.getAvailablePathForAttachments({
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
      context.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      mockIsNote.mockReturnValue(true);
      const result = await context.manager.getAvailablePathForAttachments({
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

    it('should keep the attachment file name on a note rename when renaming attachment files is off', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.renamedAttachmentFileName = '';
      context.handedOverSettings.shouldRenameAttachmentFiles = false;
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      context.settings.generatedAttachmentFileName = '${prompt}';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      mockIsNote.mockReturnValue(true);
      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.RenameNote,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        oldNotePathOrFile: 'old.md',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/img.png');
      expect(mockPromptWithPreview).not.toHaveBeenCalled();
    });

    it('should keep the attachment file name on a note rename when the renamed template is empty', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.renamedAttachmentFileName = '';
      context.handedOverSettings.shouldRenameAttachmentFiles = true;
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      context.settings.generatedAttachmentFileName = '${prompt}';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      mockIsNote.mockReturnValue(true);
      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.RenameNote,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        oldNotePathOrFile: 'old.md',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('assets/img.png');
      expect(mockPromptWithPreview).not.toHaveBeenCalled();
    });

    it('should delegate to the original function when the note path is ignored', async () => {
      const noteFile = createTFile({ path: 'ignored/note.md' });
      mockGetFileOrNull.mockReturnValue(noteFile);
      context.isPathIgnored.mockReturnValue(true);
      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'ignored/note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(result).toBe('original-path');
      expect(context.getAvailablePathForAttachmentsOriginal).toHaveBeenCalledWith('img', 'png', noteFile);
    });

    it('should delegate to the dev-utils helper for a non-note path', async () => {
      mockGetFileOrNull.mockReturnValue(null);
      mockIsNote.mockReturnValue(false);
      const result = await context.manager.getAvailablePathForAttachments({
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
      await context.manager.getAvailablePathForAttachments({
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
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      const result = await context.manager.getAvailablePathForAttachments({
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
      context.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: false,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(context.getAvailablePath).toHaveBeenCalledWith('assets/img', 'png');
      expect(result).toBe('assets/img.png');
    });

    it('should use the duplicate-checked available path with an empty extension', async () => {
      context.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: '',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: false,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      expect(context.getAvailablePath).toHaveBeenCalledWith('assets/img', '');
    });

    it('should create the missing attachment folder when folder creation is not skipped', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.handedOverSettings.emptyFolderBehavior = EmptyFolderBehavior.DeleteWithEmptyParents;
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      context.exists.mockResolvedValue(false);
      await context.manager.getAvailablePathForAttachments({
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
      expect(context.create).not.toHaveBeenCalled();
    });

    it('should create a gitkeep file when the empty folder behavior is Keep', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.handedOverSettings.emptyFolderBehavior = EmptyFolderBehavior.Keep;
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      context.exists.mockResolvedValue(false);
      await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: `${IMPORT_FILES_PREFIX}img`,
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: false
      });
      expect(context.create).toHaveBeenCalledWith('assets/.gitkeep', '');
    });

    it('should not re-create the gitkeep file when a peer device already synced it (re #16)', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.handedOverSettings.emptyFolderBehavior = EmptyFolderBehavior.Keep;
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      /*
       * The attachment folder does not exist yet, but its `.gitkeep` placeholder
       * was already synced onto disk from another device.
       */
      context.exists.mockImplementation((path) => Promise.resolve(path === 'assets/.gitkeep'));
      await context.manager.getAvailablePathForAttachments({
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
      expect(context.create).not.toHaveBeenCalled();
    });

    it('should not create the folder when it already exists', async () => {
      context.settings.attachmentFolderPath = 'assets';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(null);
      mockIsNote.mockReturnValue(true);
      context.exists.mockResolvedValue(true);
      await context.manager.getAvailablePathForAttachments({
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
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const link = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 2, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([link]);
      mockExtractLinkFile.mockReturnValue(oldFile);
      const result = await context.manager.getAvailablePathForAttachments({
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
      expect(mockGetLinks).toHaveBeenCalled();
    });
  });

  describe('getCursorLine (via getAvailablePathForAttachments)', () => {
    it('should skip non-reference-cache links and links with no resolved file', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
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
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([nonReferenceCacheLink, unresolvedReferenceCacheLink, nonMatchingReferenceCacheLink, matchingReferenceCacheLink]);
      mockExtractLinkFile.mockReturnValueOnce(null).mockReturnValueOnce(otherFile).mockReturnValue(oldFile);
      const result = await context.manager.getAvailablePathForAttachments({
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
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const referenceCacheLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 7, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([referenceCacheLink]);
      mockExtractLinkFile.mockReturnValue(oldFile);
      const result = await context.manager.getAvailablePathForAttachments({
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
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const otherFile = createTFile({ path: 'other.png' });
      const referenceCacheLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 6, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([referenceCacheLink]);
      mockExtractLinkFile.mockReturnValue(otherFile);
      const result = await context.manager.getAvailablePathForAttachments({
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
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = 'generated';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(null);
      const result = await context.manager.getAvailablePathForAttachments({
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

  describe('single-pass link walk (via getAvailablePathForAttachments)', () => {
    it('should derive the sequence number and resolve the note cache in a single walk', async () => {
      context.settings.attachmentFolderPath = 'assets';
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      context.settings.generatedAttachmentFileName = '${sequenceNumber}';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const otherFile = createTFile({ path: 'other.png' });
      const otherLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 1, offset: 0 } }
      });
      const oldLink = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 2, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({}));
      mockGetLinks.mockReturnValue([otherLink, oldLink]);
      mockExtractLinkFile.mockImplementation(({ link }) => link === oldLink ? oldFile : otherFile);
      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      // `old.png` is the 2nd distinct attachment, and the number now comes from exactly ONE `getCacheSafe`
      // Walk (previously two — one per the collapsed getCursorLine/getSequenceNumber).
      expect(result).toBe('assets/2.png');
      expect(mockGetCacheSafe).toHaveBeenCalledTimes(1);
    });

    it('should derive the cursor line from the matching reference and feed it to the heading token', async () => {
      context.settings.attachmentFolderPath = 'assets';
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      context.settings.generatedAttachmentFileName = '${heading}';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const matchAtLine4 = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 4, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({
        headings: [
          strictProxy<HeadingCache>({ heading: 'Early', level: 1, position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 2, offset: 0 } } }),
          strictProxy<HeadingCache>({ heading: 'Late', level: 1, position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 6, offset: 0 } } })
        ]
      }));
      mockGetLinks.mockReturnValue([matchAtLine4]);
      mockExtractLinkFile.mockReturnValue(oldFile);
      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      // CursorLine 4 flows into the heading token, whose cutoff (line <= 4) selects "Early" (line 2),
      // Not "Late" (line 6).
      expect(result).toBe('assets/Early.png');
    });

    it('should keep the first matching reference when a later one also matches (line-0 first match wins)', async () => {
      context.settings.attachmentFolderPath = 'assets';
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      context.settings.generatedAttachmentFileName = '${heading}';
      const noteFile = createTFile({ path: 'note.md' });
      const oldFile = createTFile({ path: 'old.png' });
      const firstMatchAtLine0 = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 0, offset: 0 } }
      });
      const secondMatchAtLine5 = strictProxy<ReferenceCache>({
        position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 5, offset: 0 } }
      });
      mockGetFileOrNull.mockReturnValueOnce(noteFile).mockReturnValue(oldFile);
      mockIsNote.mockReturnValue(true);
      mockGetCacheSafe.mockResolvedValue(strictProxy<CachedMetadataEx>({
        headings: [
          strictProxy<HeadingCache>({ heading: 'Later', level: 1, position: { end: { col: 0, line: 0, offset: 0 }, start: { col: 0, line: 3, offset: 0 } } })
        ]
      }));
      mockGetLinks.mockReturnValue([firstMatchAtLine0, secondMatchAtLine5]);
      mockExtractLinkFile.mockReturnValue(oldFile);
      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'old.png',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
      // The first match (line 0) wins, so cursorLine is 0 → the heading token treats it as "no cursor" and
      // Emits nothing. A last-match regression would pick line 5 → cutoff line <= 5 → "Later" (line 3).
      expect(result).toBe('assets/.png');
    });
  });
});
