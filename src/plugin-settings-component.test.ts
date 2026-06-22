import type { AsyncEventRef } from 'obsidian-dev-utils/async-events';
import type { DataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import type { PathOrAbstractFile } from 'obsidian-dev-utils/obsidian/file-system';
import type { PluginEventSource } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';

import { noopAsync } from 'obsidian-dev-utils/function';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { ValueWrapper } from 'obsidian-dev-utils/value-wrapper';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { translationsMap } from './i18n/locales/translations-map.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import {
  AttachmentRenameMode,
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  PluginSettings
} from './plugin-settings.ts';
import { TokenValidator } from './token-validator.ts';

vi.mock('obsidian-dev-utils/error', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/error')>(),
  printError: vi.fn<(error: unknown) => void>()
}));

class MockDataHandler implements DataHandler {
  private data: unknown;

  public constructor(data: unknown = {}) {
    this.data = data;
  }

  public async loadData(): Promise<unknown> {
    await noopAsync();
    return this.data;
  }

  public async saveData(data: unknown): Promise<void> {
    this.data = data;
    await noopAsync();
  }
}

async function createComponent(data: unknown = {}): Promise<PluginSettingsComponent> {
  const app = App.createConfigured__().asOriginalType__();
  const validatorWrapper = ValueWrapper.unset<TokenValidator>();
  const component = new PluginSettingsComponent({
    app,
    dataHandler: new MockDataHandler(data),
    pluginEventSource: strictPluginEventSource(),
    validatorWrapper
  });
  validatorWrapper.value = new TokenValidator({
    app,
    pluginSettingsComponent: component
  });
  await component.loadWithPromises();
  return component;

  function strictPluginEventSource(): PluginEventSource {
    return strictProxy<PluginEventSource>({
      on: (): AsyncEventRef => strictProxy<AsyncEventRef>({})
    });
  }
}

function createSettings(): PluginSettings {
  return new PluginSettings();
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

beforeEach(() => {
  vi.useRealTimers();
});

describe('PluginSettingsComponent', () => {
  describe('isNoteEx', () => {
    it('should return false for a null path', async () => {
      const component = await createComponent();
      expect(component.isNoteEx(null)).toBe(false);
    });

    it('should return false for a non-note path', async () => {
      const component = await createComponent();
      expect(component.isNoteEx('foo.png')).toBe(false);
    });

    it('should return true for a markdown note path', async () => {
      const component = await createComponent();
      expect(component.isNoteEx('folder/note.md')).toBe(true);
    });

    it('should return false for a note treated as an attachment', async () => {
      const component = await createComponent();
      const pathOrFile: PathOrAbstractFile = 'drawing.excalidraw.md';
      expect(component.isNoteEx(pathOrFile)).toBe(false);
    });
  });

  describe('replaceSpecialCharacters', () => {
    it('should return the string unchanged when there are no special characters configured', async () => {
      const component = await createComponent();
      await component.editAndSave((settings) => {
        settings.specialCharacters = '';
      });
      expect(component.replaceSpecialCharacters('a?b')).toBe('a?b');
    });

    it('should replace configured special characters with the replacement', async () => {
      const component = await createComponent();
      await component.editAndSave((settings) => {
        settings.specialCharacters = '?';
        settings.specialCharactersReplacement = '-';
      });
      expect(component.replaceSpecialCharacters('a?b')).toBe('a-b');
    });
  });

  describe('path validators', () => {
    it('should accept a valid attachment folder path with tokens', async () => {
      const component = await createComponent();
      const settings = createSettings();
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      settings.attachmentFolderPath = './assets/${noteFileName}';
      const result = await component.validate(settings);
      expect(result.attachmentFolderPath).toBeUndefined();
    });

    it('should reject an attachment folder path with an unknown token', async () => {
      const component = await createComponent();
      const settings = createSettings();
      // eslint-disable-next-line no-template-curly-in-string -- Invalid token used on purpose.
      settings.attachmentFolderPath = '${unknownToken}';
      const result = await component.validate(settings);
      expect(result.attachmentFolderPath).toContain('Unknown token');
    });

    it('should accept a valid generated attachment file name with tokens', async () => {
      const component = await createComponent();
      const settings = createSettings();
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      settings.generatedAttachmentFileName = 'file-${date:{momentJsFormat:\'YYYY\'}}';
      const result = await component.validate(settings);
      expect(result.generatedAttachmentFileName).toBeUndefined();
    });
  });

  describe('specialCharactersReplacement validator', () => {
    it('should accept a replacement without invalid characters', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.specialCharactersReplacement = '-';
      const result = await component.validate(settings);
      expect(result.specialCharactersReplacement).toBeUndefined();
    });

    it('should reject a replacement containing invalid file name characters', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.specialCharactersReplacement = '?';
      const result = await component.validate(settings);
      expect(result.specialCharactersReplacement).toBe('Special character replacement must not contain invalid file name path characters.');
    });
  });

  describe('defaultImageSize validator', () => {
    it('should accept an empty default image size', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.defaultImageSize = '';
      const result = await component.validate(settings);
      expect(result.defaultImageSize).toBeUndefined();
    });

    it('should accept a pixel default image size', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.defaultImageSize = '300px';
      const result = await component.validate(settings);
      expect(result.defaultImageSize).toBeUndefined();
    });

    it('should accept a percentage default image size', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.defaultImageSize = '50%';
      const result = await component.validate(settings);
      expect(result.defaultImageSize).toBeUndefined();
    });

    it('should reject an invalid default image size', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.defaultImageSize = 'abc';
      const result = await component.validate(settings);
      expect(result.defaultImageSize).toBe('Default image size must be in pixels or percentage');
    });
  });

  describe('duplicateNameSeparator validator', () => {
    it('should accept a valid separator', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.duplicateNameSeparator = ' ';
      const result = await component.validate(settings);
      expect(result.duplicateNameSeparator).toBeUndefined();
    });

    it('should reject a separator that produces an invalid file name', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.duplicateNameSeparator = '?';
      const result = await component.validate(settings);
      expect(result.duplicateNameSeparator).toContain('invalid symbols');
    });
  });

  describe('include/exclude paths validators', () => {
    it('should accept valid regular expressions and plain paths', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.includePaths = ['/valid.*/'];
      settings.excludePaths = ['plain/path'];
      const result = await component.validate(settings);
      expect(result.includePaths).toBeUndefined();
      expect(result.excludePaths).toBeUndefined();
    });

    it('should reject an invalid regular expression in includePaths', async () => {
      const component = await createComponent();
      // The real PluginSettings setter eagerly compiles the regex and would throw, so the getter is
      // Overridden to feed the validator an invalid pattern directly.
      const settings = createSettings();
      Object.defineProperty(settings, 'includePaths', {
        configurable: true,
        get: (): string[] => ['/[/']
      });
      const result = await component.validate(settings);
      expect(result.includePaths).toBe('Invalid regular expression /[/');
    });

    it('should reject an invalid regular expression in excludePaths', async () => {
      const component = await createComponent();
      const settings = createSettings();
      Object.defineProperty(settings, 'excludePaths', {
        configurable: true,
        get: (): string[] => ['/(/']
      });
      const result = await component.validate(settings);
      expect(result.excludePaths).toBe('Invalid regular expression /(/');
    });
  });

  describe('customTokensStr validator', () => {
    it('should accept valid custom tokens code when not debounced', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.customTokensStr = 'registerCustomToken(\'foo\', () => \'bar\');';
      const result = await component.validate(settings);
      expect(result.customTokensStr).toBeUndefined();
    });

    it('should reject invalid custom tokens code when not debounced', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.customTokensStr = 'this is not valid javascript {{{';
      const result = await component.validate(settings);
      expect(result.customTokensStr).toBe('Invalid custom tokens code');
    });

    it('should use the debounced validator when debouncing is enabled', async () => {
      const component = await createComponent();
      vi.useFakeTimers();
      component.shouldDebounceCustomTokensValidation = true;
      const settings = createSettings();
      settings.customTokensStr = 'this is not valid javascript {{{';
      // First call schedules the debounced validation and returns the previous (undefined) result.
      const firstResult = await component.validate(settings);
      expect(firstResult.customTokensStr).toBeUndefined();

      // Once the debounce window elapses, the impl runs and stores the failure result.
      await vi.advanceTimersByTimeAsync(2000);
      const secondResult = await component.validate(settings);
      expect(secondResult.customTokensStr).toBe('Invalid custom tokens code');
    });
  });

  describe('legacy settings converter', () => {
    it('should map warningVersion into version', async () => {
      const component = await createComponent({ warningVersion: '8.0.0' });
      expect(component.settings.version).toBe('8.0.0');
    });

    it('should map autoRenameFiles into shouldRenameAttachmentFiles', async () => {
      const component = await createComponent({ autoRenameFiles: true });
      expect(component.settings.shouldRenameAttachmentFiles).toBe(true);
    });

    it('should map autoRenameFolder into shouldRenameAttachmentFolder', async () => {
      const component = await createComponent({ autoRenameFolder: false });
      expect(component.settings.shouldRenameAttachmentFolder).toBe(false);
    });

    it('should map shouldRenameAttachments into shouldRenameAttachmentFolder', async () => {
      const component = await createComponent({ shouldRenameAttachments: false });
      expect(component.settings.shouldRenameAttachmentFolder).toBe(false);
    });

    it('should map deleteOrphanAttachments into shouldDeleteOrphanAttachments', async () => {
      const component = await createComponent({ deleteOrphanAttachments: true });
      expect(component.settings.shouldDeleteOrphanAttachments).toBe(true);
    });

    it('should map renameCollectedFiles into shouldRenameCollectedAttachments', async () => {
      const component = await createComponent({ renameCollectedFiles: true });
      expect(component.settings.shouldRenameCollectedAttachments).toBe(true);
    });

    it('should map shouldConvertPastedImagesToJpeg true into OnlyPastedClipboardPngImages', async () => {
      const component = await createComponent({ shouldConvertPastedImagesToJpeg: true });
      expect(component.settings.convertImagesToJpegMode).toBe(ConvertImagesToJpegMode.OnlyPastedClipboardPngImages);
    });

    it('should map convertImagesToJpeg false into None', async () => {
      const component = await createComponent({ convertImagesToJpeg: false });
      expect(component.settings.convertImagesToJpegMode).toBe(ConvertImagesToJpegMode.None);
    });

    it('should map shouldDuplicateCollectedAttachments true into Copy', async () => {
      const component = await createComponent({ shouldDuplicateCollectedAttachments: true });
      expect(component.settings.collectAttachmentUsedByMultipleNotesMode).toBe(CollectAttachmentUsedByMultipleNotesMode.Copy);
    });

    it('should map shouldDuplicateCollectedAttachments false into Skip', async () => {
      const component = await createComponent({ shouldDuplicateCollectedAttachments: false });
      expect(component.settings.collectAttachmentUsedByMultipleNotesMode).toBe(CollectAttachmentUsedByMultipleNotesMode.Skip);
    });

    it('should map keepEmptyAttachmentFolders into shouldKeepEmptyAttachmentFolders and then emptyFolderBehavior Keep', async () => {
      const component = await createComponent({ keepEmptyAttachmentFolders: true });
      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.Keep);
    });

    it('should map keepEmptyAttachmentFolders false into emptyFolderBehavior DeleteWithEmptyParents', async () => {
      const component = await createComponent({ keepEmptyAttachmentFolders: false });
      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.DeleteWithEmptyParents);
    });

    it('should prefer emptyAttachmentFolderBehavior over keepEmptyAttachmentFolders', async () => {
      const component = await createComponent({
        emptyAttachmentFolderBehavior: EmptyFolderBehavior.Delete,
        keepEmptyAttachmentFolders: true
      });
      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.Delete);
    });

    it('should map replaceWhitespace true into a whitespace replacement appended to special characters', async () => {
      const component = await createComponent({ replaceWhitespace: true });
      expect(component.settings.specialCharacters).toContain(' ');
      expect(component.settings.specialCharactersReplacement).toBe('-');
    });

    it('should map replaceWhitespace false into an empty whitespace replacement', async () => {
      const component = await createComponent({ replaceWhitespace: false });
      expect(component.settings.specialCharactersReplacement).toBe('-');
    });

    it('should map whitespaceReplacement into special characters and replacement', async () => {
      const component = await createComponent({ whitespaceReplacement: '_' });
      expect(component.settings.specialCharacters.endsWith(' ')).toBe(true);
      expect(component.settings.specialCharactersReplacement).toBe('_');
    });

    it('should comment out legacy custom tokens for versions earlier than 9.0.0', async () => {
      const component = await createComponent({
        customTokensStr: 'registerCustomToken();',
        version: '8.0.0'
      });
      expect(component.settings.customTokensStr).toContain('// registerCustomToken();');
    });

    it('should reset markdownUrlFormat for deprecated values before 9.2.0', async () => {
      const component = await createComponent({
        // eslint-disable-next-line no-template-curly-in-string -- Deprecated token value.
        markdownUrlFormat: '${generatedAttachmentFilePath}',
        version: '9.1.0'
      });
      expect(component.settings.markdownUrlFormat).toBe('');
    });

    it('should upgrade the special characters default before 9.16.0', async () => {
      const component = await createComponent({
        specialCharacters: '#^[]|*\\<>:?',
        version: '9.15.0'
      });
      expect(component.settings.specialCharacters).toBe('#^[]|*\\<>:?/');
    });

    it('should convert legacy moment-format tokens into the new format', async () => {
      const component = await createComponent({
        // eslint-disable-next-line no-template-curly-in-string -- Legacy token format.
        generatedAttachmentFileName: 'file-${date:YYYYMMDD}'
      });
      // eslint-disable-next-line no-template-curly-in-string -- Expected converted token format.
      expect(component.settings.generatedAttachmentFileName).toBe('file-${date:{momentJsFormat:\'YYYYMMDD\'}}');
    });

    it('should leave settings at defaults when no legacy keys are present', async () => {
      const component = await createComponent({});
      expect(component.settings.shouldRenameAttachmentFolder).toBe(true);
      expect(component.settings.attachmentRenameMode).toBe(AttachmentRenameMode.OnlyPastedImages);
    });
  });
});
