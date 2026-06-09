import type { App as ObsidianApp } from 'obsidian';
import type { DataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import type { PluginEventSource } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';
import type { PartialDeep } from 'type-fest';

import { noopAsync } from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/rename-delete-handler';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeAll,
  describe,
  expect,
  it
} from 'vitest';

import type { Plugin } from './plugin.ts';

import { translationsMap } from './i18n/locales/translations-map.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import {
  AttachmentRenameMode,
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  PluginSettings
} from './plugin-settings.ts';

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

function createComponent(data: unknown = {}): PluginSettingsComponent {
  const app = App.createConfigured__();
  const plugin = strictProxy<Plugin>({ app: castTo<PartialDeep<ObsidianApp>>(app.asOriginalType__()) });
  return new PluginSettingsComponent({
    dataHandler: new MockDataHandler(data),
    plugin,
    pluginEventSource: strictProxy<PluginEventSource>({})
  });
}

function createSettings(): PluginSettings {
  return new PluginSettings();
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('PluginSettingsComponent', () => {
  describe('path validators', () => {
    it('should accept a valid attachment folder path with tokens', async () => {
      const component = createComponent();
      const settings = createSettings();
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      settings.attachmentFolderPath = './assets/${noteFileName}';
      const result = await component.validate(settings);
      expect(result.attachmentFolderPath).toBeUndefined();
    });

    it('should reject an attachment folder path with an unknown token', async () => {
      const component = createComponent();
      const settings = createSettings();
      // eslint-disable-next-line no-template-curly-in-string -- Invalid token used on purpose.
      settings.attachmentFolderPath = '${unknownToken}';
      const result = await component.validate(settings);
      expect(result.attachmentFolderPath).toContain('Unknown token');
    });

    it('should accept a valid generated attachment file name with tokens', async () => {
      const component = createComponent();
      const settings = createSettings();
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      settings.generatedAttachmentFileName = 'file-${date:{momentJsFormat:\'YYYY\'}}';
      const result = await component.validate(settings);
      expect(result.generatedAttachmentFileName).toBeUndefined();
    });
  });

  describe('specialCharactersReplacement validator', () => {
    it('should accept a replacement without invalid characters', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.specialCharactersReplacement = '-';
      const result = await component.validate(settings);
      expect(result.specialCharactersReplacement).toBeUndefined();
    });

    it('should reject a replacement containing invalid file name characters', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.specialCharactersReplacement = '?';
      const result = await component.validate(settings);
      expect(result.specialCharactersReplacement).toBe('Special character replacement must not contain invalid file name path characters.');
    });
  });

  describe('defaultImageSize validator', () => {
    it('should accept an empty default image size', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.defaultImageSize = '';
      const result = await component.validate(settings);
      expect(result.defaultImageSize).toBeUndefined();
    });

    it('should accept a pixel default image size', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.defaultImageSize = '300px';
      const result = await component.validate(settings);
      expect(result.defaultImageSize).toBeUndefined();
    });

    it('should accept a percentage default image size', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.defaultImageSize = '50%';
      const result = await component.validate(settings);
      expect(result.defaultImageSize).toBeUndefined();
    });

    it('should reject an invalid default image size', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.defaultImageSize = 'abc';
      const result = await component.validate(settings);
      expect(result.defaultImageSize).toBe('Default image size must be in pixels or percentage');
    });
  });

  describe('duplicateNameSeparator validator', () => {
    it('should accept a valid separator', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.duplicateNameSeparator = ' ';
      const result = await component.validate(settings);
      expect(result.duplicateNameSeparator).toBeUndefined();
    });

    it('should reject a separator that produces an invalid file name', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.duplicateNameSeparator = '?';
      const result = await component.validate(settings);
      expect(result.duplicateNameSeparator).toContain('invalid symbols');
    });
  });

  describe('include/exclude paths validators', () => {
    it('should accept valid regular expressions and plain paths', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.includePaths = ['/valid.*/'];
      settings.excludePaths = ['plain/path'];
      const result = await component.validate(settings);
      expect(result.includePaths).toBeUndefined();
      expect(result.excludePaths).toBeUndefined();
    });

    it('should reject an invalid regular expression in includePaths', async () => {
      const component = createComponent();
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
      const component = createComponent();
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
      const component = createComponent();
      const settings = createSettings();
      settings.customTokensStr = 'registerCustomToken(\'foo\', () => \'bar\');';
      const result = await component.validate(settings);
      expect(result.customTokensStr).toBeUndefined();
    });

    it('should reject invalid custom tokens code when not debounced', async () => {
      const component = createComponent();
      const settings = createSettings();
      settings.customTokensStr = 'this is not valid javascript {{{';
      const result = await component.validate(settings);
      expect(result.customTokensStr).toBe('Invalid custom tokens code');
    });

    it('should use the debounced validator when debouncing is enabled', async () => {
      const component = createComponent();
      component.shouldDebounceCustomTokensValidation = true;
      const settings = createSettings();
      settings.customTokensStr = 'this is not valid javascript {{{';
      // First call schedules the debounced validation and returns the previous (undefined) result.
      const result = await component.validate(settings);
      expect(result.customTokensStr).toBeUndefined();
    });
  });

  describe('legacy settings converter', () => {
    it('should map warningVersion into version', async () => {
      const component = createComponent({ warningVersion: '8.0.0' });
      await component.loadFromFile(true);
      expect(component.settings.version).toBe('8.0.0');
    });

    it('should map autoRenameFiles into shouldRenameAttachmentFiles', async () => {
      const component = createComponent({ autoRenameFiles: true });
      await component.loadFromFile(true);
      expect(component.settings.shouldRenameAttachmentFiles).toBe(true);
    });

    it('should map autoRenameFolder into shouldRenameAttachmentFolder', async () => {
      const component = createComponent({ autoRenameFolder: false });
      await component.loadFromFile(true);
      expect(component.settings.shouldRenameAttachmentFolder).toBe(false);
    });

    it('should map shouldRenameAttachments into shouldRenameAttachmentFolder', async () => {
      const component = createComponent({ shouldRenameAttachments: false });
      await component.loadFromFile(true);
      expect(component.settings.shouldRenameAttachmentFolder).toBe(false);
    });

    it('should map deleteOrphanAttachments into shouldDeleteOrphanAttachments', async () => {
      const component = createComponent({ deleteOrphanAttachments: true });
      await component.loadFromFile(true);
      expect(component.settings.shouldDeleteOrphanAttachments).toBe(true);
    });

    it('should map renameCollectedFiles into shouldRenameCollectedAttachments', async () => {
      const component = createComponent({ renameCollectedFiles: true });
      await component.loadFromFile(true);
      expect(component.settings.shouldRenameCollectedAttachments).toBe(true);
    });

    it('should map shouldConvertPastedImagesToJpeg true into OnlyPastedClipboardPngImages', async () => {
      const component = createComponent({ shouldConvertPastedImagesToJpeg: true });
      await component.loadFromFile(true);
      expect(component.settings.convertImagesToJpegMode).toBe(ConvertImagesToJpegMode.OnlyPastedClipboardPngImages);
    });

    it('should map convertImagesToJpeg false into None', async () => {
      const component = createComponent({ convertImagesToJpeg: false });
      await component.loadFromFile(true);
      expect(component.settings.convertImagesToJpegMode).toBe(ConvertImagesToJpegMode.None);
    });

    it('should map shouldDuplicateCollectedAttachments true into Copy', async () => {
      const component = createComponent({ shouldDuplicateCollectedAttachments: true });
      await component.loadFromFile(true);
      expect(component.settings.collectAttachmentUsedByMultipleNotesMode).toBe(CollectAttachmentUsedByMultipleNotesMode.Copy);
    });

    it('should map shouldDuplicateCollectedAttachments false into Skip', async () => {
      const component = createComponent({ shouldDuplicateCollectedAttachments: false });
      await component.loadFromFile(true);
      expect(component.settings.collectAttachmentUsedByMultipleNotesMode).toBe(CollectAttachmentUsedByMultipleNotesMode.Skip);
    });

    it('should map keepEmptyAttachmentFolders into shouldKeepEmptyAttachmentFolders and then emptyFolderBehavior Keep', async () => {
      const component = createComponent({ keepEmptyAttachmentFolders: true });
      await component.loadFromFile(true);
      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.Keep);
    });

    it('should map keepEmptyAttachmentFolders false into emptyFolderBehavior DeleteWithEmptyParents', async () => {
      const component = createComponent({ keepEmptyAttachmentFolders: false });
      await component.loadFromFile(true);
      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.DeleteWithEmptyParents);
    });

    it('should prefer emptyAttachmentFolderBehavior over keepEmptyAttachmentFolders', async () => {
      const component = createComponent({
        emptyAttachmentFolderBehavior: EmptyFolderBehavior.Delete,
        keepEmptyAttachmentFolders: true
      });
      await component.loadFromFile(true);
      expect(component.settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.Delete);
    });

    it('should map replaceWhitespace true into a whitespace replacement appended to special characters', async () => {
      const component = createComponent({ replaceWhitespace: true });
      await component.loadFromFile(true);
      expect(component.settings.specialCharacters).toContain(' ');
      expect(component.settings.specialCharactersReplacement).toBe('-');
    });

    it('should map replaceWhitespace false into an empty whitespace replacement', async () => {
      const component = createComponent({ replaceWhitespace: false });
      await component.loadFromFile(true);
      expect(component.settings.specialCharactersReplacement).toBe('-');
    });

    it('should map whitespaceReplacement into special characters and replacement', async () => {
      const component = createComponent({ whitespaceReplacement: '_' });
      await component.loadFromFile(true);
      expect(component.settings.specialCharacters.endsWith(' ')).toBe(true);
      expect(component.settings.specialCharactersReplacement).toBe('_');
    });

    it('should comment out legacy custom tokens for versions earlier than 9.0.0', async () => {
      const component = createComponent({
        customTokensStr: 'registerCustomToken();',
        version: '8.0.0'
      });
      await component.loadFromFile(true);
      expect(component.settings.customTokensStr).toContain('// registerCustomToken();');
    });

    it('should reset markdownUrlFormat for deprecated values before 9.2.0', async () => {
      const component = createComponent({
        // eslint-disable-next-line no-template-curly-in-string -- Deprecated token value.
        markdownUrlFormat: '${generatedAttachmentFilePath}',
        version: '9.1.0'
      });
      await component.loadFromFile(true);
      expect(component.settings.markdownUrlFormat).toBe('');
    });

    it('should upgrade the special characters default before 9.16.0', async () => {
      const component = createComponent({
        specialCharacters: '#^[]|*\\<>:?',
        version: '9.15.0'
      });
      await component.loadFromFile(true);
      expect(component.settings.specialCharacters).toBe('#^[]|*\\<>:?/');
    });

    it('should convert legacy moment-format tokens into the new format', async () => {
      const component = createComponent({
        // eslint-disable-next-line no-template-curly-in-string -- Legacy token format.
        generatedAttachmentFileName: 'file-${date:YYYYMMDD}'
      });
      await component.loadFromFile(true);
      // eslint-disable-next-line no-template-curly-in-string -- Expected converted token format.
      expect(component.settings.generatedAttachmentFileName).toBe('file-${date:{momentJsFormat:\'YYYYMMDD\'}}');
    });

    it('should leave settings at defaults when no legacy keys are present', async () => {
      const component = createComponent({});
      await component.loadFromFile(true);
      expect(component.settings.shouldRenameAttachmentFolder).toBe(true);
      expect(component.settings.attachmentRenameMode).toBe(AttachmentRenameMode.OnlyPastedImages);
    });
  });
});
