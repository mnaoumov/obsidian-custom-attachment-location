import type { FileStats } from 'obsidian';
import type { MockInstance } from 'vitest';

import { Notice } from 'obsidian';
import { printError } from 'obsidian-dev-utils/error';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { join } from 'obsidian-dev-utils/path';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { Plugin } from './plugin.ts';
import type { Substitutions as SubstitutionsType } from './substitutions.ts';

import {
  getAttachmentFolderFullPathForPath,
  getGeneratedAttachmentFileBaseName
} from './attachment-path.ts';
import {
  Substitutions,
  TokenValidationMode,
  validateFileName,
  validatePath
} from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';

vi.mock('obsidian', async (importOriginal) => {
  const actual = await importOriginal<typeof import('obsidian')>();
  // eslint-disable-next-line @typescript-eslint/no-extraneous-class -- Mock records constructed instances for assertions.
  class MockNotice {
    public static instances: MockNotice[] = [];

    public constructor(_message: unknown, _timeout?: number) {
      MockNotice.instances.push(this);
    }
  }
  return {
    ...actual,
    Notice: MockNotice
  };
});

vi.mock('obsidian-dev-utils/error', () => ({
  printError: vi.fn()
}));

vi.mock('obsidian-dev-utils/html-element', () => ({
  appendCodeBlock: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/i18n/i18n', () => {
  const deepProxy: unknown = new Proxy(() => 'translated', {
    get: (): unknown => deepProxy
  });
  return {
    t: vi.fn((selector: (translations: unknown) => unknown) => {
      selector(deepProxy);
      return 'translated';
    })
  };
});

vi.mock('obsidian-dev-utils/path', async (importOriginal) => {
  const actual = await importOriginal<typeof import('obsidian-dev-utils/path')>();
  return {
    ...actual,
    join: vi.fn()
  };
});

vi.mock('./substitutions.ts', () => {
  const fillTemplate = vi.fn<(template: string) => Promise<string>>();
  return {
    Substitutions: class {
      public fillTemplate = fillTemplate;
      public noteFolderPath = 'notes';

      public constructor(public readonly params: unknown) {
      }
    },
    TokenValidationMode: {
      Error: 'Error',
      Skip: 'Skip',
      Validate: 'Validate'
    },
    validateFileName: vi.fn<() => Promise<string>>(),
    validatePath: vi.fn<() => Promise<string>>()
  };
});

interface NoticeStaticLike {
  instances: unknown[];
}

interface SettingsLike {
  attachmentFolderPath: string;
  collectedAttachmentFileName: string;
  generatedAttachmentFileName: string;
  renamedAttachmentFileName: string;
}

interface SubstitutionsMockLike {
  fillTemplate: ReturnType<typeof vi.fn<(template: string) => Promise<string>>>;
  noteFolderPath: string;
}

const mockJoin = vi.mocked(join);
const mockValidateFileName = vi.mocked(validateFileName);
const mockValidatePath = vi.mocked(validatePath);
const mockPrintError = vi.mocked(printError);

function getFillTemplate(): SubstitutionsMockLike['fillTemplate'] {
  return castTo<SubstitutionsMockLike>(new Substitutions(castTo<ConstructorParameters<typeof Substitutions>[0]>({}))).fillTemplate;
}

describe('attachment-path', () => {
  let plugin: Plugin;
  let pluginSettingsComponent: PluginSettingsComponent;
  let settings: SettingsLike;
  let replaceSpecialCharacters: ReturnType<typeof vi.fn<(str: string) => string>>;
  let errorSpy: MockInstance<typeof console.error>;

  beforeEach(() => {
    vi.clearAllMocks();
    settings = {
      attachmentFolderPath: './assets',
      collectedAttachmentFileName: '',
      generatedAttachmentFileName: 'generated',
      renamedAttachmentFileName: ''
    };
    replaceSpecialCharacters = vi.fn<(str: string) => string>().mockImplementation((str) => str);
    plugin = strictProxy<Plugin>({
      replaceSpecialCharacters: (str: string) => replaceSpecialCharacters(str)
    });
    pluginSettingsComponent = strictProxy<PluginSettingsComponent>({
      settings: castTo<PluginSettingsComponent['settings']>(settings)
    });
    mockJoin.mockImplementation((...parts: string[]) => parts.filter((p) => p !== '').join('/'));
    mockValidatePath.mockResolvedValue('');
    mockValidateFileName.mockResolvedValue('');
    getFillTemplate().mockResolvedValue('assets');
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  describe('getAttachmentFolderFullPathForPath', () => {
    it('should resolve the attachment folder path for the note', async () => {
      getFillTemplate().mockResolvedValue('assets');
      const result = await getAttachmentFolderFullPathForPath(
        plugin,
        ActionContext.SaveAttachment,
        'note.md',
        'img.png',
        pluginSettingsComponent
      );
      expect(result).toBe('assets');
    });

    it('should resolve a relative path against the note folder path', async () => {
      settings.attachmentFolderPath = './assets';
      getFillTemplate().mockResolvedValue('./assets');
      const stat = strictProxy<FileStats>({ ctime: 0, mtime: 0, size: 0 });
      const result = await getAttachmentFolderFullPathForPath(
        plugin,
        ActionContext.SaveAttachment,
        'note.md',
        'img.png',
        pluginSettingsComponent,
        'old.md',
        new ArrayBuffer(0),
        stat
      );
      expect(result).toBe('notes/./assets');
      expect(mockJoin).toHaveBeenCalledWith('notes', './assets');
    });
  });

  describe('getGeneratedAttachmentFileBaseName', () => {
    function createSubstitutions(actionContext: ActionContext): SubstitutionsType {
      return castTo<SubstitutionsType>({ actionContext, fillTemplate: getFillTemplate(), noteFolderPath: 'notes' });
    }

    it('should use the collected attachment file name template for CollectAttachments', async () => {
      settings.collectedAttachmentFileName = 'collected';
      getFillTemplate().mockResolvedValue('collected');
      const result = await getGeneratedAttachmentFileBaseName(plugin, createSubstitutions(ActionContext.CollectAttachments), pluginSettingsComponent);
      expect(result).toBe('collected');
    });

    it('should use the renamed attachment file name template for RenameNote', async () => {
      settings.renamedAttachmentFileName = 'renamed';
      getFillTemplate().mockResolvedValue('renamed');
      const result = await getGeneratedAttachmentFileBaseName(plugin, createSubstitutions(ActionContext.RenameNote), pluginSettingsComponent);
      expect(result).toBe('renamed');
    });

    it('should fall back to the generated attachment file name template by default', async () => {
      getFillTemplate().mockResolvedValue('generated');
      const result = await getGeneratedAttachmentFileBaseName(plugin, createSubstitutions(ActionContext.SaveAttachment), pluginSettingsComponent);
      expect(result).toBe('generated');
    });

    it('should fall back to the generated template when the chosen template is empty', async () => {
      settings.collectedAttachmentFileName = '';
      getFillTemplate().mockResolvedValue('generated');
      const result = await getGeneratedAttachmentFileBaseName(plugin, createSubstitutions(ActionContext.CollectAttachments), pluginSettingsComponent);
      expect(result).toBe('generated');
    });

    it('should validate the file name part of the resolved path', async () => {
      getFillTemplate().mockResolvedValue('folder/file');
      await getGeneratedAttachmentFileBaseName(plugin, createSubstitutions(ActionContext.SaveAttachment), pluginSettingsComponent);
      expect(mockValidateFileName).toHaveBeenCalledWith(expect.objectContaining({ fileName: 'file', tokenValidationMode: TokenValidationMode.Error }));
    });

    it('should throw and notify when the path validation fails', async () => {
      getFillTemplate().mockResolvedValue('bad');
      // First call inside resolvePathTemplate passes; the validation in getGeneratedAttachmentFileBaseName fails.
      mockValidatePath.mockResolvedValueOnce('').mockResolvedValue('invalid path');
      await expect(getGeneratedAttachmentFileBaseName(plugin, createSubstitutions(ActionContext.SaveAttachment), pluginSettingsComponent)).rejects.toThrow(
        'is invalid'
      );
      expect(errorSpy).toHaveBeenCalled();
    });

    it('should throw and notify when the file name validation fails', async () => {
      getFillTemplate().mockResolvedValue('bad');
      mockValidateFileName.mockResolvedValue('invalid file name');
      await expect(getGeneratedAttachmentFileBaseName(plugin, createSubstitutions(ActionContext.SaveAttachment), pluginSettingsComponent)).rejects.toThrow(
        'is invalid'
      );
    });

    it('should use an empty file name when the resolved path is empty', async () => {
      getFillTemplate().mockResolvedValue('');
      await getGeneratedAttachmentFileBaseName(plugin, createSubstitutions(ActionContext.SaveAttachment), pluginSettingsComponent);
      expect(mockValidateFileName).toHaveBeenCalledWith(expect.objectContaining({ fileName: '' }));
    });
  });

  describe('resolvePathTemplate (via getAttachmentFolderFullPathForPath)', () => {
    it('should clean special characters and trailing dots from each path part', async () => {
      getFillTemplate().mockResolvedValue('a /b. ');
      replaceSpecialCharacters.mockImplementation((str) => str.replace('a', 'A'));
      const result = await getAttachmentFolderFullPathForPath(plugin, ActionContext.SaveAttachment, 'note.md', 'img.png', pluginSettingsComponent);
      expect(result).toBe('A/b');
    });

    it('should preserve single and double dot path parts', async () => {
      getFillTemplate().mockResolvedValue('./..');
      mockJoin.mockReturnValue('notes/..');
      const result = await getAttachmentFolderFullPathForPath(plugin, ActionContext.SaveAttachment, 'note.md', 'img.png', pluginSettingsComponent);
      expect(result).toBe('notes/..');
    });

    it('should throw and notify when the resolved path validation fails', async () => {
      getFillTemplate().mockResolvedValue('bad');
      mockValidatePath.mockResolvedValue('invalid');
      await expect(getAttachmentFolderFullPathForPath(plugin, ActionContext.SaveAttachment, 'note.md', 'img.png', pluginSettingsComponent)).rejects.toThrow(
        'is invalid'
      );
      expect(mockPrintError).toHaveBeenCalled();
      const noticeInstances = castTo<NoticeStaticLike>(Notice).instances;
      expect(noticeInstances.length).toBeGreaterThan(0);
    });

    it('should normalize an empty resolved path to an empty string', async () => {
      getFillTemplate().mockResolvedValue('.');
      mockJoin.mockReturnValue('.');
      const result = await getAttachmentFolderFullPathForPath(plugin, ActionContext.SaveAttachment, 'note.md', 'img.png', pluginSettingsComponent);
      expect(result).toBe('');
    });

    it('should throw when the resolved path is still relative after normalization', async () => {
      getFillTemplate().mockResolvedValue('../outside');
      mockJoin.mockReturnValue('../outside');
      await expect(getAttachmentFolderFullPathForPath(plugin, ActionContext.SaveAttachment, 'note.md', 'img.png', pluginSettingsComponent)).rejects.toThrow(
        'should be absolute'
      );
    });
  });
});
