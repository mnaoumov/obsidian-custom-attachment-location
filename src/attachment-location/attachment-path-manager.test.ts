import type { CachedMetadataEx } from '@mnaoumov/obsidian-lib/metadata-cache';
import type {
  App,
  FileStats,
  HeadingCache,
  Reference,
  ReferenceCache,
  TFile,
  Vault
} from 'obsidian';

import {
  AttachmentPathContext,
  DUMMY_PATH,
  getAvailablePathForAttachments
} from '@mnaoumov/obsidian-lib/attachment-path';
import { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import {
  getAbstractFileOrNull,
  getFileOrNull,
  getPath,
  isNote
} from '@mnaoumov/obsidian-lib/file-system';
import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { extractLinkFile } from '@mnaoumov/obsidian-lib/link';
import {
  getCacheSafe,
  getLinks
} from '@mnaoumov/obsidian-lib/metadata-cache';
import {
  createFolderSafe,
  CreateFolderSafeResult,
  EmptyFolderBehavior
} from '@mnaoumov/obsidian-lib/vault';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { HandedOverSettings } from '../advanced-rename-and-delete-handler/advanced-rename-and-delete-handler.ts';
import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from '../original-attachment-names/original-attachment-names-component.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { PluginSettings } from '../settings/plugin-settings.ts';
import type { TokenValidator } from '../tokens/token-validator.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { promptWithPreview } from '../tokens/prompt/prompt-with-preview-modal.ts';
import { Substitutions } from '../tokens/substitutions.ts';
import { ActionContext } from '../tokens/token-evaluator-context.ts';
import { TokenValidationMode } from '../tokens/token-validator.ts';
import { AttachmentPathManager } from './attachment-path-manager.ts';
import { findIdenticalAttachmentFile } from './identical-attachment.ts';
import { IMPORT_FILES_PREFIX } from './share-receiver-import-files-patch-component.ts';

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

vi.mock('@mnaoumov/obsidian-lib/attachment-path', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/attachment-path')>(),
  getAvailablePathForAttachments: vi.fn<typeof getAvailablePathForAttachments>()
}));

vi.mock('@mnaoumov/obsidian-lib/file-system', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/file-system')>(),
  getAbstractFileOrNull: vi.fn<typeof getAbstractFileOrNull>(),
  getFileOrNull: vi.fn<typeof getFileOrNull>(),
  getPath: vi.fn<typeof getPath>(),
  isNote: vi.fn<typeof isNote>()
}));

vi.mock('@mnaoumov/obsidian-lib/link', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/link')>(),
  extractLinkFile: vi.fn<typeof extractLinkFile>()
}));

vi.mock('@mnaoumov/obsidian-lib/metadata-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/metadata-cache')>(),
  getCacheSafe: vi.fn<typeof getCacheSafe>(),
  getLinks: vi.fn<typeof getLinks>()
}));

vi.mock('@mnaoumov/obsidian-lib/vault', async (importOriginal) => ({
  ...await importOriginal<typeof import('@mnaoumov/obsidian-lib/vault')>(),
  createFolderSafe: vi.fn<typeof createFolderSafe>()
}));

vi.mock('./identical-attachment.ts', () => ({
  findIdenticalAttachmentFile: vi.fn()
}));

vi.mock('../tokens/prompt/prompt-with-preview-modal.ts', async (importOriginal) => ({
  ...await importOriginal<typeof import('../tokens/prompt/prompt-with-preview-modal.ts')>(),
  promptWithPreview: vi.fn<typeof promptWithPreview>()
}));

const mockGetAvailablePathForAttachments = vi.mocked(getAvailablePathForAttachments);
const mockGetAbstractFileOrNull = vi.mocked(getAbstractFileOrNull);
const mockGetFileOrNull = vi.mocked(getFileOrNull);
const mockGetPath = vi.mocked(getPath);
const mockIsNote = vi.mocked(isNote);
const mockExtractLinkFile = vi.mocked(extractLinkFile);
const mockGetLinks = vi.mocked(getLinks);
const mockGetCacheSafe = vi.mocked(getCacheSafe);
const mockCreateFolderSafe = vi.mocked(createFolderSafe);
const mockPromptWithPreview = vi.mocked(promptWithPreview);
const mockFindIdenticalAttachmentFile = vi.mocked(findIdenticalAttachmentFile);

// The handed-over settings live in `Advanced Rename and Delete Handler` since 12.0.0. Mutable here so a test
// can still change one mid-run, exactly as it used to change .
interface MutableHandedOverSettings {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  emptyFolderBehavior: EmptyFolderBehavior;
  readonly notePriorities: readonly string[];
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  shouldRenameAttachmentFiles: boolean;
  readonly treatAsAttachmentExtensions: readonly string[];
}

interface TestContext {
  readonly create: ReturnType<typeof vi.fn<Vault['create']>>;
  readonly exists: ReturnType<typeof vi.fn<Vault['exists']>>;
  readonly expectArrival: ReturnType<typeof vi.fn<OriginalAttachmentNamesComponent['expectArrival']>>;
  readonly getAvailablePath: ReturnType<typeof vi.fn<Vault['getAvailablePath']>>;
  readonly getAvailablePathForAttachmentsOriginal: ReturnType<typeof vi.fn<Vault['getAvailablePathForAttachments']>>;
  readonly getConfig: ReturnType<typeof vi.fn<(name: string) => unknown>>;
  readonly handedOverSettings: MutableHandedOverSettings;
  readonly isNoteEx: ReturnType<typeof vi.fn<PluginSettingsComponent['isNoteEx']>>;
  readonly isPathIgnored: ReturnType<typeof vi.fn<HandedOverSettingsComponent['isPathIgnored']>>;
  readonly manager: AttachmentPathManager;
  readonly originalAttachmentNames: Map<string, string>;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly readBinary: ReturnType<typeof vi.fn<Vault['readBinary']>>;
  readonly reportUnknown: ReturnType<typeof vi.fn<OriginalAttachmentNamesComponent['reportUnknown']>>;
  readonly settings: PluginSettings;
  readonly tokenValidator: TokenValidator;
  readonly validateFileName: ReturnType<typeof vi.fn<TokenValidator['validateFileName']>>;
  readonly validatePath: ReturnType<typeof vi.fn<TokenValidator['validatePath']>>;
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
    collectedAttachmentFolderPath: '',
    duplicateNameSeparator: ' ',
    generatedAttachmentFileName: 'generated',
    insertedLinkText: '',
    renamedAttachmentFileName: '',
    shouldFollowObsidianAttachmentLocation: false,
    shouldRenameCollectedAttachments: false,
    specialCharacters: '',
    specialCharactersReplacement: '-'
  });

  const exists = vi.fn<Vault['exists']>().mockResolvedValue(true);
  const create = vi.fn<Vault['create']>();
  const readBinary = vi.fn<Vault['readBinary']>().mockResolvedValue(new ArrayBuffer(0));
  const getAvailablePath = vi.fn<Vault['getAvailablePath']>().mockImplementation((path, extension) => extension ? `${path}.${extension}` : path);
  const getAvailablePathForAttachmentsOriginal = vi.fn<Vault['getAvailablePathForAttachments']>().mockResolvedValue('original-path');
  const getConfig = vi.fn<(name: string) => unknown>().mockReturnValue('/');

  const vault = strictProxy<Vault>({
    create,
    exists,
    getAvailablePath,
    getConfig: castTo<Vault['getConfig']>(getConfig),
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

  const originalAttachmentNames = new Map<string, string>();
  const expectArrival = vi.fn<OriginalAttachmentNamesComponent['expectArrival']>();
  const reportUnknown = vi.fn<OriginalAttachmentNamesComponent['reportUnknown']>();
  const originalAttachmentNamesComponent = strictProxy<OriginalAttachmentNamesComponent>({
    expectArrival,
    get: (path: string) => originalAttachmentNames.get(path),
    reportUnknown
  });

  const manager = new AttachmentPathManager({
    app,
    getAvailablePathForAttachmentsOriginal,
    handedOverSettingsComponent,
    originalAttachmentNamesComponent,
    pluginNoticeComponent: new PluginNoticeComponent({ app, pluginName: 'Custom Attachment Location' }),
    pluginSettingsComponent,
    tokenValidator
  });

  return {
    create,
    exists,
    expectArrival,
    getAvailablePath,
    getAvailablePathForAttachmentsOriginal,
    getConfig,
    handedOverSettings,
    isNoteEx,
    isPathIgnored,
    manager,
    originalAttachmentNames,
    pluginSettingsComponent,
    readBinary,
    reportUnknown,
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
  mockFindIdenticalAttachmentFile.mockResolvedValue(null);
  mockGetAbstractFileOrNull.mockReturnValue(null);
  mockGetFileOrNull.mockReturnValue(null);
  mockGetPath.mockImplementation((_app, pathOrFile) => typeof pathOrFile === 'string' ? pathOrFile : castTo<TFile>(pathOrFile).path);
  mockIsNote.mockReturnValue(true);
  mockGetAvailablePathForAttachments.mockResolvedValue('obsidian-lib-path');
  mockGetLinks.mockReturnValue([]);
  mockGetCacheSafe.mockResolvedValue(null);
  mockExtractLinkFile.mockReturnValue(null);
  mockCreateFolderSafe.mockResolvedValue(CreateFolderSafeResult.Created);
  mockPromptWithPreview.mockResolvedValue('prompted');
  context = createManager();
});

describe('AttachmentPathManager', () => {
  describe('inserted link text', () => {
    interface PrepareOptions {
      readonly baseName?: string;
      readonly context?: AttachmentPathContext;
      readonly extension?: string;
      readonly notePath?: null | string;
      readonly originalFileName?: string;
      readonly readContent?: () => Promise<ArrayBuffer>;
    }
    function file(path = 'renamed.pdf'): TFile {
      return createTFile({ extension: 'pdf', name: 'renamed.pdf', path });
    }

    async function prepare(options: PrepareOptions = {}): Promise<string> {
      const note = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockImplementation(({ pathOrFile }) => pathOrFile === 'note.md' ? note : null);
      mockIsNote.mockReturnValue(true);
      return await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: options.baseName ?? 'renamed',
        attachmentFileExtension: options.extension ?? 'pdf',
        context: options.context ?? AttachmentPathContext.Unknown,
        notePathOrFile: options.notePath === undefined ? 'note.md' : options.notePath,
        oldAttachmentPathOrFile: 'incoming.pdf',
        originalAttachmentFileName: options.originalFileName ?? 'Original.pdf',
        readAttachmentFileContent: options.readContent ?? null,
        shouldSkipGeneratedAttachmentFileName: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });
    }

    it('reads the saved arrival name after the attachment has been collected or renamed, including string formats', () => {
      context.settings.insertedLinkText = '{{OriginalAttachmentFileName:{case:"upper"}}}.{{originalAttachmentFileExtension}}';
      context.originalAttachmentNames.set('renamed.pdf', 'original report.pdf');
      expect(context.manager.getInsertedLinkText({ attachmentFile: file(), notePath: 'note.md' })).toBe('ORIGINAL REPORT.pdf');
    });

    it('uses the current name when an older attachment has no saved original', () => {
      context.settings.insertedLinkText = '{{originalAttachmentFileName}}';
      expect(context.manager.getInsertedLinkText({ attachmentFile: file(), notePath: 'note.md' })).toBe('renamed');
      expect(context.reportUnknown).toHaveBeenCalledWith({ actionContext: ActionContext.Unknown, currentFileName: 'renamed.pdf', path: 'renamed.pdf' });
    });

    it('supports literal text and leaves empty templates at the default', () => {
      context.settings.insertedLinkText = 'Read this';
      expect(context.manager.getInsertedLinkText({ attachmentFile: file(), notePath: 'note.md' })).toBe('Read this');
      context.settings.insertedLinkText = '';
      expect(context.manager.getInsertedLinkText({ attachmentFile: file(), notePath: 'note.md' })).toBeUndefined();
    });

    it('requires asynchronous import preparation for templates using other tokens', () => {
      context.settings.insertedLinkText = '{{noteFileName}}';
      expect(context.manager.getInsertedLinkText({ attachmentFile: file(), notePath: 'note.md' })).toBeUndefined();
    });

    it('uses a prepared general template before synchronous link generation', async () => {
      context.settings.insertedLinkText = '{{noteFileName}}: {{originalAttachmentFileName}}';
      const path = await prepare({ readContent: () => Promise.resolve(new ArrayBuffer(0)) });
      expect(context.manager.getInsertedLinkText({ attachmentFile: file(path), notePath: 'note.md' })).toBe('note: Original');
    });

    it('awaits asynchronous custom tokens before the importer generates its link', async () => {
      Substitutions.registerCustomTokens('registerCustomToken(\'linkLabel\', async (ctx) => { await Promise.resolve(); return ctx.originalAttachmentFileName + \' async\'; });');
      context.settings.insertedLinkText = '{{linkLabel}}';
      try {
        const path = await prepare();
        expect(context.manager.takeInsertedLinkText({ attachmentPath: path, notePath: 'note.md' })).toBe('Original async');
      } finally {
        Substitutions.registerCustomTokens('');
      }
    });

    it('leaves the link at its default when the evaluated template is empty', async () => {
      context.settings.insertedLinkText = '{{originalAttachmentFileName}}';
      const emptyPath = await prepare({ originalFileName: '' });
      expect(context.manager.takeInsertedLinkText({ attachmentPath: emptyPath, notePath: 'note.md' })).toBeUndefined();
    });

    it('discards expired preparations and preparations made with a different template', async () => {
      context.settings.insertedLinkText = '{{noteFileName}}';
      const path = await prepare();
      const clock = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 60_001);
      try {
        expect(context.manager.takeInsertedLinkText({ attachmentPath: path, notePath: 'note.md' })).toBeUndefined();
      } finally {
        clock.mockRestore();
      }
      await prepare();
      // eslint-disable-next-line require-atomic-updates -- Each test owns this settings fixture.
      context.settings.insertedLinkText = 'different';
      expect(context.manager.takeInsertedLinkText({ attachmentPath: path, notePath: 'note.md' })).toBeUndefined();
    });

    it('evicts the oldest unused preparation rather than growing for every dry path probe', async () => {
      context.settings.insertedLinkText = '{{noteFileName}}';
      const count = 101;
      for (let index = 0; index < count; index++) {
        await prepare({ baseName: `attachment-${index.toString()}` });
      }
      expect(context.manager.takeInsertedLinkText({ attachmentPath: 'assets/attachment-0.pdf', notePath: 'note.md' })).toBeUndefined();
      expect(context.manager.takeInsertedLinkText({ attachmentPath: 'assets/attachment-100.pdf', notePath: 'note.md' })).toBe('note');
    });

    it.each([
      { extension: 'png' },
      { baseName: DUMMY_PATH },
      { notePath: null },
      { context: AttachmentPathContext.DeleteNote }
    ])('does not prepare aliases for images, placeholders, missing notes or deletion (%j)', async (options) => {
      context.settings.insertedLinkText = '{{noteFileName}}';
      const path = await prepare(options);
      expect(context.manager.takeInsertedLinkText({ attachmentPath: path, notePath: 'note.md' })).toBeUndefined();
    });
  });

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

    it('should use the collected attachment folder path template for CollectAttachments', async () => {
      context.settings.attachmentFolderPath = '_Attachments';
      context.settings.collectedAttachmentFolderPath = './exported';
      const result = await context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFileName: 'img.png',
        notePath: 'notes/note.md'
      });
      expect(result).toBe('notes/exported');
    });

    it('should fall back to the new attachment folder path when the collected template is empty', async () => {
      context.settings.attachmentFolderPath = '_Attachments';
      context.settings.collectedAttachmentFolderPath = '';
      const result = await context.manager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFileName: 'img.png',
        notePath: 'notes/note.md'
      });
      expect(result).toBe('_Attachments');
    });

    describe('when following Obsidian\'s own attachment location', () => {
      async function resolveFor(configuredPath: unknown, notePath = 'notes/note.md', actionContext = ActionContext.SaveAttachment): Promise<string> {
        context.settings.shouldFollowObsidianAttachmentLocation = true;
        context.getConfig.mockReturnValue(configuredPath);
        return await context.manager.getAttachmentFolderFullPathForPath({
          actionContext,
          attachmentFileName: 'img.png',
          notePath
        });
      }

      it('should resolve each of the four Obsidian modes the way Obsidian does', async () => {
        expect(await resolveFor('/')).toBe('');
        expect(await resolveFor('assets')).toBe('assets');
        expect(await resolveFor('./')).toBe('notes');
        expect(await resolveFor('.')).toBe('notes');
        expect(await resolveFor('./attachments')).toBe('notes/attachments');
        expect(context.getConfig).toHaveBeenCalledWith('attachmentFolderPath');
      });

      it('should resolve the note-relative modes for a note in the vault root', async () => {
        expect(await resolveFor('./', 'note.md')).toBe('');
        expect(await resolveFor('./attachments', 'note.md')).toBe('attachments');
      });

      it('should not run the template machinery over a folder name the user typed into Obsidian', async () => {
        context.settings.specialCharacters = '#';
        const folderName = 'Media #1/{{noteFileName}}';
        expect(await resolveFor(folderName)).toBe(folderName);
        expect(context.validatePath).not.toHaveBeenCalled();
      });

      it('should treat a missing Obsidian setting as the vault root', async () => {
        expect(await resolveFor(undefined)).toBe('');
      });

      it('should ignore the template while the mode is on', async () => {
        context.settings.attachmentFolderPath = '_Attachments';
        expect(await resolveFor('./attachments')).toBe('notes/attachments');
      });

      it('should let an explicit collected-attachment folder win for collecting', async () => {
        context.settings.collectedAttachmentFolderPath = './exported';
        expect(await resolveFor('./attachments', 'notes/note.md', ActionContext.CollectAttachments)).toBe('notes/exported');
      });

      it('should collect into Obsidian\'s location when no collected-attachment folder is set', async () => {
        context.settings.collectedAttachmentFolderPath = '';
        expect(await resolveFor('./attachments', 'notes/note.md', ActionContext.CollectAttachments)).toBe('notes/attachments');
      });
    });

    it('should leave every other action context on the new attachment folder path', async () => {
      context.settings.attachmentFolderPath = '_Attachments';
      context.settings.collectedAttachmentFolderPath = './exported';
      for (const actionContext of [ActionContext.SaveAttachment, ActionContext.MoveAttachmentToProperFolder, ActionContext.RenameNote]) {
        const result = await context.manager.getAttachmentFolderFullPathForPath({
          actionContext,
          attachmentFileName: 'img.png',
          notePath: 'notes/note.md'
        });
        expect(result, `Action context '${actionContext}' should use the new attachment folder path`).toBe('_Attachments');
      }
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
      context.settings.generatedAttachmentFileName = '{{prompt}}';
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
      context.settings.collectedAttachmentFileName = 'collected-{{sequenceNumber:{length:2}}}';
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

  describe('original attachment names', () => {
    const STACKING_TEMPLATE = '{{noteFileName}}-{{originalAttachmentFileName}}';

    function createAttachmentFile(path: string): TFile {
      const name = path.split('/').at(-1) ?? path;
      return createTFile({
        extension: 'png',
        name,
        path,
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
    }

    async function collect(attachmentFile: TFile): Promise<null | string> {
      return await context.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: castTo<Reference>({ link: 'x', original: 'x' }),
        sequenceNumber: 0
      });
    }

    beforeEach(() => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.shouldRenameCollectedAttachments = true;
      context.settings.collectedAttachmentFileName = STACKING_TEMPLATE;
    });

    it('should build a collected name on the recorded original, so a second collect does not stack the note name', async () => {
      // The first collect moved `img.png` to `assets/note-img.png`, and the record followed it there.
      context.originalAttachmentNames.set('assets/note-img.png', 'img.png');

      expect(await collect(createAttachmentFile('assets/note-img.png'))).toBeNull();
      expect(context.reportUnknown).not.toHaveBeenCalled();
    });

    it('should fall back to the current name and report it when no original is on record', async () => {
      expect(await collect(createAttachmentFile('old/img.png'))).toBe('assets/note-img.png');
      expect(context.reportUnknown).toHaveBeenCalledExactlyOnceWith({
        actionContext: ActionContext.CollectAttachments,
        currentFileName: 'img.png',
        path: 'old/img.png'
      });
    });

    it('should not report an unknown original when the template never reads it', async () => {
      context.settings.collectedAttachmentFileName = 'collected';

      expect(await collect(createAttachmentFile('old/img.png'))).toBe('assets/collected.png');
      expect(context.reportUnknown).not.toHaveBeenCalled();
    });

    it('should read the current name through {{attachmentFileName}}, whatever the record says', async () => {
      context.settings.collectedAttachmentFileName = '{{attachmentFileName}}';
      context.originalAttachmentNames.set('old/img.png', 'arrived.png');

      expect(await collect(createAttachmentFile('old/img.png'))).toBe('assets/img.png');
    });

    it('should read the recorded original in the folder template too', async () => {
      context.settings.attachmentFolderPath = 'assets/{{originalAttachmentFileName}}';
      context.settings.collectedAttachmentFileName = '{{attachmentFileName}}';
      context.originalAttachmentNames.set('old/img.png', 'arrived.png');

      expect(await collect(createAttachmentFile('old/img.png'))).toBe('assets/arrived/img.png');
    });

    it('should expect a new attachment to arrive under the name the caller says it arrived with', async () => {
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockImplementation(({ pathOrFile }) => pathOrFile === 'note.md' ? noteFile : null);
      context.settings.generatedAttachmentFileName = '{{originalAttachmentFileName}}';

      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'note-Pasted image',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'note-Pasted image.png',
        originalAttachmentFileName: 'Pasted image.png',
        readAttachmentFileContent: null,
        shouldSkipGeneratedAttachmentFileName: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });

      expect(result).toBe('assets/note-Pasted image.png');
      expect(context.expectArrival).toHaveBeenCalledExactlyOnceWith('assets/note-Pasted image.png', 'Pasted image.png');
    });

    it('should expect a new attachment to arrive under the name it is asked about by default', async () => {
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockImplementation(({ pathOrFile }) => pathOrFile === 'note.md' ? noteFile : null);
      context.settings.generatedAttachmentFileName = '{{noteFileName}}-{{originalAttachmentFileName}}';

      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'Recording 1',
        attachmentFileExtension: 'webm',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'Recording 1.webm',
        readAttachmentFileContent: null,
        shouldSkipMissingAttachmentFolderCreation: true
      });

      expect(result).toBe('assets/note-Recording 1.webm');
      expect(context.expectArrival).toHaveBeenCalledExactlyOnceWith('assets/note-Recording 1.webm', 'Recording 1.webm');
      expect(context.reportUnknown).not.toHaveBeenCalled();
    });

    it('should expect a downloaded image to arrive under its downloaded name', async () => {
      await context.manager.getDownloadedImagePath({
        actionContext: ActionContext.SaveAttachment,
        downloadedContent: new ArrayBuffer(4),
        fileExtension: 'png',
        fileName: 'my-image',
        noteFilePath: 'note.md'
      });

      expect(context.expectArrival).toHaveBeenCalledExactlyOnceWith('assets/generated.png', 'my-image.png');
    });

    it('should read the recorded original of an existing attachment on a note rename, and expect no arrival', async () => {
      context.handedOverSettings.shouldRenameAttachmentFiles = true;
      context.settings.renamedAttachmentFileName = STACKING_TEMPLATE;
      const noteFile = createTFile({ path: 'new-note.md' });
      const attachmentFile = createAttachmentFile('assets/note-img.png');
      context.originalAttachmentNames.set(attachmentFile.path, 'img.png');
      mockGetFileOrNull.mockImplementation(({ pathOrFile }) => {
        if (pathOrFile === 'new-note.md') {
          return noteFile;
        }
        return pathOrFile === attachmentFile.path ? attachmentFile : null;
      });

      const result = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'note-img',
        attachmentFileExtension: 'png',
        context: AttachmentPathContext.RenameNote,
        notePathOrFile: 'new-note.md',
        oldAttachmentPathOrFile: attachmentFile.path,
        oldNotePathOrFile: 'note.md',
        readAttachmentFileContent: null,
        shouldSkipDuplicateCheck: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });

      expect(result).toBe('assets/new-note-img.png');
      expect(context.expectArrival).not.toHaveBeenCalled();
      expect(context.reportUnknown).not.toHaveBeenCalled();
    });
  });

  describe('getProperAttachmentPath, for an attachment parked under a duplicate suffix', () => {
    function createParkedFile(basename: string): TFile {
      return createTFile({
        basename,
        extension: 'png',
        name: `${basename}.png`,
        path: `assets/${basename}.png`,
        stat: strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 })
      });
    }

    async function getProperPath(attachmentFile: TFile): Promise<null | string> {
      return await context.manager.getProperAttachmentPath({
        actionContext: ActionContext.CollectAttachments,
        attachmentFile,
        noteFilePath: 'note.md',
        reference: castTo<Reference>({ link: 'x', original: 'x' }),
        sequenceNumber: 0
      });
    }

    beforeEach(() => {
      context.settings.shouldRenameCollectedAttachments = true;
      context.settings.collectedAttachmentFileName = 'img';
      context.settings.attachmentFolderPath = 'assets';
    });

    it('should leave it where it is while another file holds the proper path, so auto-collect converges', async () => {
      mockGetAbstractFileOrNull.mockReturnValue(createTFile({ path: 'assets/img.png' }));

      await expect(getProperPath(createParkedFile('img 1'))).resolves.toBeNull();
      expect(mockGetAbstractFileOrNull).toHaveBeenCalledWith(expect.objectContaining({ pathOrFile: 'assets/img.png' }));
    });

    it('should hand back the proper path when the file holding it is identical, so the duplicate is merged', async () => {
      const identicalFile = createTFile({ path: 'assets/img.png' });
      mockGetAbstractFileOrNull.mockReturnValue(identicalFile);
      mockFindIdenticalAttachmentFile.mockResolvedValue(identicalFile);
      const parkedFile = createParkedFile('img 1');

      await expect(getProperPath(parkedFile)).resolves.toBe('assets/img.png');
      expect(mockFindIdenticalAttachmentFile).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
        attachmentPathOrFile: parkedFile,
        destinationPath: 'assets/img.png',
        pluginSettingsComponent: context.pluginSettingsComponent
      }));
    });

    it('should move it onto the proper path once that path is free', async () => {
      await expect(getProperPath(createParkedFile('img 1'))).resolves.toBe('assets/img.png');
    });

    it('should honour the configured duplicate separator', async () => {
      context.settings.duplicateNameSeparator = '_';
      mockGetAbstractFileOrNull.mockReturnValue(createTFile({ path: 'assets/img.png' }));

      await expect(getProperPath(createParkedFile('img_2'))).resolves.toBeNull();
      await expect(getProperPath(createParkedFile('img 2'))).resolves.toBe('assets/img.png');
    });

    it('should move a file whose name is not the proper name plus a suffix', async () => {
      mockGetAbstractFileOrNull.mockReturnValue(createTFile({ path: 'assets/img.png' }));

      await expect(getProperPath(createParkedFile('photo 1'))).resolves.toBe('assets/img.png');
      await expect(getProperPath(createParkedFile('img copy'))).resolves.toBe('assets/img.png');
    });
  });

  describe('getAvailablePathForAttachments', () => {
    it('prepares arrival-name link text before a renamed attachment is created, once per insertion', async () => {
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockImplementation(({ pathOrFile }) => pathOrFile === 'note.md' ? noteFile : null);
      mockIsNote.mockReturnValue(true);
      context.settings.insertedLinkText = '{{originalAttachmentFileName}} ({{generatedAttachmentFileName}})';

      const path = await context.manager.getAvailablePathForAttachments({
        attachmentFileBaseName: 'renamed',
        attachmentFileExtension: 'pdf',
        context: AttachmentPathContext.Unknown,
        notePathOrFile: 'note.md',
        oldAttachmentPathOrFile: 'renamed.pdf',
        originalAttachmentFileName: 'original report.pdf',
        readAttachmentFileContent: null,
        shouldSkipGeneratedAttachmentFileName: true,
        shouldSkipMissingAttachmentFolderCreation: true
      });

      expect(context.manager.takeInsertedLinkText({ attachmentPath: path, notePath: 'other.md' })).toBeUndefined();
      expect(context.manager.takeInsertedLinkText({ attachmentPath: path, notePath: 'note.md' })).toBe('original report (renamed.pdf)');
      expect(context.manager.takeInsertedLinkText({ attachmentPath: path, notePath: 'note.md' })).toBeUndefined();
    });

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
      expect(result).toBe('obsidian-lib-path');
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

    describe('special characters in a kept file name', () => {
      async function resolveKept(attachmentFileBaseName: string, shouldReplaceSpecialCharactersInKeptFileName = false): Promise<string> {
        context.settings.attachmentFolderPath = 'assets';
        context.settings.specialCharacters = '#';
        const noteFile = createTFile({ path: 'note.md' });
        mockGetFileOrNull.mockReturnValue(noteFile);
        mockIsNote.mockReturnValue(true);
        return await context.manager.getAvailablePathForAttachments({
          attachmentFileBaseName,
          attachmentFileExtension: 'txt',
          context: AttachmentPathContext.Unknown,
          notePathOrFile: 'note.md',
          oldAttachmentPathOrFile: 'old.txt',
          readAttachmentFileContent: null,
          shouldReplaceSpecialCharactersInKeptFileName,
          shouldSkipDuplicateCheck: true,
          shouldSkipGeneratedAttachmentFileName: true,
          shouldSkipMissingAttachmentFolderCreation: true
        });
      }

      it('should replace them when asked', async () => {
        expect(await resolveKept('foo#bar', true)).toBe('assets/foo-bar.txt');
      });

      it('should keep them when not asked', async () => {
        expect(await resolveKept('foo#bar')).toBe('assets/foo#bar.txt');
      });

      it('should keep a name that would clean to nothing', async () => {
        context.settings.specialCharactersReplacement = '';
        expect(await resolveKept('#', true)).toBe('assets/#.txt');
      });

      it('should not clean a share-sheet import, whose name is already generated', async () => {
        expect(await resolveKept(`${IMPORT_FILES_PREFIX}foo#bar`, true)).toBe('assets/foo#bar.txt');
      });
    });

    it('should keep the attachment file name on a note rename when renaming attachment files is off', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.renamedAttachmentFileName = '';
      context.handedOverSettings.shouldRenameAttachmentFiles = false;
      context.settings.generatedAttachmentFileName = '{{prompt}}';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockImplementation(({ pathOrFile }) => pathOrFile === 'note.md' ? noteFile : null);
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
      context.settings.generatedAttachmentFileName = '{{prompt}}';
      const noteFile = createTFile({ path: 'note.md' });
      mockGetFileOrNull.mockImplementation(({ pathOrFile }) => pathOrFile === 'note.md' ? noteFile : null);
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

    it('should delegate to the obsidian-lib helper for a non-note path', async () => {
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
      expect(result).toBe('obsidian-lib-path');
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
      context.settings.generatedAttachmentFileName = '{{sequenceNumber}}';
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
      // walk (previously two — one per the collapsed getCursorLine/getSequenceNumber).
      expect(result).toBe('assets/2.png');
      expect(mockGetCacheSafe).toHaveBeenCalledTimes(1);
    });

    it('should derive the cursor line from the matching reference and feed it to the heading token', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = '{{heading}}';
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
      // cursorLine 4 flows into the heading token, whose cutoff (line <= 4) selects "Early" (line 2),
      // not "Late" (line 6).
      expect(result).toBe('assets/Early.png');
    });

    it('should keep the first matching reference when a later one also matches (line-0 first match wins)', async () => {
      context.settings.attachmentFolderPath = 'assets';
      context.settings.generatedAttachmentFileName = '{{heading}}';
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
      // emits nothing. A last-match regression would pick line 5 → cutoff line <= 5 → "Later" (line 3).
      expect(result).toBe('assets/.png');
    });
  });
});
