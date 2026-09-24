import type { AsyncEventRef } from 'obsidian-dev-utils/async-events';
import type { DataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import type { PathOrAbstractFile } from 'obsidian-dev-utils/obsidian/file-system';
import type { PluginEventSource } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';

import { noopAsync } from 'obsidian-dev-utils/function';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/vault';
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

import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';

import { translationsMap } from './i18n/locales/translations-map.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import {
  AttachmentRenameMode,
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  PluginSettings,
  RenameAttachmentsCreatedByOtherPluginsMode
} from './plugin-settings.ts';
import { TokenValidator } from './token-validator.ts';

vi.mock('obsidian-dev-utils/error', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/error')>(),
  printError: vi.fn<(error: unknown) => void>()
}));

class JsonDataHandler implements DataHandler {
  public saveCount = 0;
  private json: string | undefined;

  public constructor(data: unknown) {
    this.json = JSON.stringify(data);
  }

  public async loadData(): Promise<unknown> {
    await noopAsync();
    return this.json === undefined ? undefined : JSON.parse(this.json);
  }

  public async saveData(data: unknown): Promise<void> {
    this.saveCount++;
    this.json = JSON.stringify(data);
    await noopAsync();
  }
}

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

async function createComponent(data: unknown = {}, dataHandler: DataHandler = new MockDataHandler(data)): Promise<PluginSettingsComponent> {
  const app = App.createConfigured__().asOriginalType__();
  const validatorWrapper = ValueWrapper.unset<TokenValidator>();
  const component = new PluginSettingsComponent({
    app,
    dataHandler,
    handedOverSettingsComponent: strictProxy<HandedOverSettingsComponent>({
      isTreatedAsAttachment: (path) => path.endsWith('.excalidraw.md')
    }),
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
  describe('loadFromFile', () => {
    // A user who never saves a setting used to have no data.json at all, so a later default change moved
    // Them silently: that is what 13.0.0's shouldFollowObsidianAttachmentLocation flip did.
    it('should write the full settings record when no data.json exists', async () => {
      const dataHandler = new MockDataHandler(null);
      await createComponent(null, dataHandler);
      const saved = await dataHandler.loadData() as Partial<PluginSettings>;
      expect(saved.shouldFollowObsidianAttachmentLocation).toBe(true);
      expect(saved.attachmentFolderPath).toBe('./assets/{{noteFileName}}');
    });

    it('should write the full settings record when loadData answers undefined', async () => {
      const dataHandler = new MockDataHandler(undefined);
      await createComponent(undefined, dataHandler);
      const saved = await dataHandler.loadData() as Partial<PluginSettings>;
      expect(saved.shouldFollowObsidianAttachmentLocation).toBe(true);
    });

    /*
     * Obsidian stores data.json as JSON, so the handler round-trips through it. The private backing fields of
     * `PluginSettings` used to reach the record as keys holding `undefined`, which JSON drops, so every load
     * found the file different from what it would write and saved it again — and a save Obsidian reported back
     * as an external change reloaded, and saved, without end.
     */
    it('should not write data.json again when loading the record it wrote', async () => {
      const dataHandler = new JsonDataHandler({ shouldFollowObsidianAttachmentLocation: false });
      const component = await createComponent(undefined, dataHandler);
      const savesAfterFirstLoad = dataHandler.saveCount;
      const written = await dataHandler.loadData() as Record<string, unknown>;

      await component.loadFromFile(false);

      expect(dataHandler.saveCount).toBe(savesAfterFirstLoad);
      expect(Object.keys(written).filter((key) => key.startsWith('_'))).toEqual([]);
    });

    it('should keep a stored value the default now disagrees with', async () => {
      const dataHandler = new MockDataHandler({ shouldFollowObsidianAttachmentLocation: false });
      const component = await createComponent(undefined, dataHandler);
      expect(component.settings.shouldFollowObsidianAttachmentLocation).toBe(false);
      const saved = await dataHandler.loadData() as Partial<PluginSettings>;
      expect(saved.shouldFollowObsidianAttachmentLocation).toBe(false);
    });
  });

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
      settings.attachmentFolderPath = './assets/{{noteFileName}}';
      const result = await component.validate(settings);
      expect(result.attachmentFolderPath).toBeUndefined();
    });

    it('should reject an attachment folder path with an unknown token', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.attachmentFolderPath = '{{unknownToken}}';
      const result = await component.validate(settings);
      expect(result.attachmentFolderPath).toContain('Unknown token');
    });

    it('should reject an attachment folder path in the retired token syntax, naming the replacement', async () => {
      const component = await createComponent();
      const settings = createSettings();
      // eslint-disable-next-line no-template-curly-in-string -- The retired plugin token syntax, not a JS template literal.
      settings.attachmentFolderPath = './assets/${noteFileName}';
      const result = await component.validate(settings);
      expect(result.attachmentFolderPath).toContain('Write it as \'{{noteFileName}}\' instead.');
    });

    it('should accept a valid collected attachment folder path with tokens', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.collectedAttachmentFolderPath = './{{noteFileName}}.assets';
      const result = await component.validate(settings);
      expect(result.collectedAttachmentFolderPath).toBeUndefined();
    });

    it('should accept an empty collected attachment folder path, which means the new attachment location', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.collectedAttachmentFolderPath = '';
      const result = await component.validate(settings);
      expect(result.collectedAttachmentFolderPath).toBeUndefined();
    });

    it('should reject a collected attachment folder path with an unknown token', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.collectedAttachmentFolderPath = '{{unknownToken}}';
      const result = await component.validate(settings);
      expect(result.collectedAttachmentFolderPath).toContain('Unknown token');
    });

    it('should accept a valid generated attachment file name with tokens', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.generatedAttachmentFileName = 'file-{{date:{momentJsFormat:\'YYYY\'}}}';
      const result = await component.validate(settings);
      expect(result.generatedAttachmentFileName).toBeUndefined();
    });

    it('should accept the scalar date format shorthand in the generated attachment file name', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.generatedAttachmentFileName = 'file-{{date:YYYY-MM-DD}}';
      const result = await component.validate(settings);
      expect(result.generatedAttachmentFileName).toBeUndefined();
    });

    it('should accept valid regular expressions and plain paths in the exclude lists', async () => {
      const component = await createComponent();
      const settings = createSettings();
      // Both shapes in one list: a plain path, which the validator skips, and a regular expression, which
      // It compiles.
      settings.excludePathsFromMultipleNotesCheck = ['plain/path', String.raw`/\.excalidraw\.md$/`];
      const result = await component.validate(settings);
      expect(result.excludePathsFromMultipleNotesCheck).toBeUndefined();
    });

    it('should reject an invalid regular expression in an exclude list', async () => {
      const component = await createComponent();
      // The real PluginSettings setter eagerly compiles the regex and would throw, so the getter is
      // Overridden to feed the validator an invalid pattern directly.
      const settings = createSettings();
      Object.defineProperty(settings, 'excludePathsFromMultipleNotesCheck', {
        configurable: true,
        get: (): string[] => ['/[/']
      });
      const result = await component.validate(settings);
      expect(result.excludePathsFromMultipleNotesCheck).toBe('Invalid regular expression /[/');
    });
  });

  describe('excludeExtensionsFromMultipleNotesCheck validator', () => {
    it('should accept extensions in every spelling the matcher understands', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.excludeExtensionsFromMultipleNotesCheck = ['af', '.PSD', 'excalidraw.md', ''];
      const result = await component.validate(settings);
      expect(result.excludeExtensionsFromMultipleNotesCheck).toBeUndefined();
    });

    it('should reject a path typed into the extension list, which would silently match nothing', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.excludeExtensionsFromMultipleNotesCheck = ['shared/project.af'];
      const result = await component.validate(settings);
      expect(result.excludeExtensionsFromMultipleNotesCheck).toContain('must not contain a path separator');
    });

    it('should reject a backslash path too, which is what a Windows user pastes', async () => {
      const component = await createComponent();
      const settings = createSettings();
      settings.excludeExtensionsFromMultipleNotesCheck = [String.raw`shared\project.af`];
      const result = await component.validate(settings);
      expect(result.excludeExtensionsFromMultipleNotesCheck).toContain('must not contain a path separator');
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

  describe('customTokensStr validator', () => {
    it('should accept valid custom tokens code when not debounced', async () => {
      const component = await createComponent();
      const settings = createSettings();
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
      settings.customTokensStr = 'registerCustomToken(\'foo\', () => \'bar\');';
      const result = await component.validate(settings);
      expect(result.customTokensStr).toBeUndefined();
    });

    it('should reject invalid custom tokens code when not debounced', async () => {
      const component = await createComponent();
      const settings = createSettings();
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
      settings.customTokensStr = 'this is not valid javascript {{{';
      const result = await component.validate(settings);
      expect(result.customTokensStr).toBe('Invalid custom tokens code');
    });

    it('should use the debounced validator when debouncing is enabled', async () => {
      const component = await createComponent();
      vi.useFakeTimers();
      component.shouldDebounceCustomTokensValidation = true;
      const settings = createSettings();
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
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
    it('should keep the default attachmentFolderPath when the record has no such key', async () => {
      const component = await createComponent({ shouldFollowObsidianAttachmentLocation: false });
      expect(component.settings.attachmentFolderPath).toBe('./assets/{{noteFileName}}');
    });

    it('should map warningVersion into version', async () => {
      const component = await createComponent({ warningVersion: '8.0.0' });
      expect(component.settings.version).toBe('8.0.0');
    });

    it('should gather autoRenameFiles into the proposed rename/delete settings', async () => {
      const component = await createComponent({ autoRenameFiles: true });
      expect(component.settings.proposedRenameDeleteSettings?.shouldRenameAttachmentFiles).toBe(true);
    });

    it('should gather autoRenameFolder into the proposed rename/delete settings', async () => {
      const component = await createComponent({ autoRenameFolder: false });
      expect(component.settings.proposedRenameDeleteSettings?.shouldRenameAttachmentFolder).toBe(false);
    });

    it('should gather shouldRenameAttachments into the proposed rename/delete settings', async () => {
      const component = await createComponent({ shouldRenameAttachments: false });
      expect(component.settings.proposedRenameDeleteSettings?.shouldRenameAttachmentFolder).toBe(false);
    });

    // Renamed on the way across: the other plugin spells this setting `shouldHandleDeletions`.
    it('should gather deleteOrphanAttachments into the proposed rename/delete settings', async () => {
      const component = await createComponent({ deleteOrphanAttachments: true });
      expect(component.settings.proposedRenameDeleteSettings?.shouldHandleDeletions).toBe(true);
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

    it('should map shouldRenameAttachmentsCreatedByOtherPlugins true into All', async () => {
      const component = await createComponent({ shouldRenameAttachmentsCreatedByOtherPlugins: true });
      expect(component.settings.renameAttachmentsCreatedByOtherPluginsMode).toBe(RenameAttachmentsCreatedByOtherPluginsMode.All);
    });

    it('should map shouldRenameAttachmentsCreatedByOtherPlugins false into None', async () => {
      const component = await createComponent({ shouldRenameAttachmentsCreatedByOtherPlugins: false });
      expect(component.settings.renameAttachmentsCreatedByOtherPluginsMode).toBe(RenameAttachmentsCreatedByOtherPluginsMode.None);
    });

    it('should map keepEmptyAttachmentFolders into shouldKeepEmptyAttachmentFolders and then emptyFolderBehavior Keep', async () => {
      const component = await createComponent({ keepEmptyAttachmentFolders: true });
      expect(component.settings.proposedRenameDeleteSettings?.emptyFolderBehavior).toBe(EmptyFolderBehavior.Keep);
    });

    it('should map keepEmptyAttachmentFolders false into emptyFolderBehavior DeleteWithEmptyParents', async () => {
      const component = await createComponent({ keepEmptyAttachmentFolders: false });
      expect(component.settings.proposedRenameDeleteSettings?.emptyFolderBehavior).toBe(EmptyFolderBehavior.DeleteWithEmptyParents);
    });

    it('should prefer emptyAttachmentFolderBehavior over keepEmptyAttachmentFolders', async () => {
      const component = await createComponent({
        emptyAttachmentFolderBehavior: EmptyFolderBehavior.Delete,
        keepEmptyAttachmentFolders: true
      });
      expect(component.settings.proposedRenameDeleteSettings?.emptyFolderBehavior).toBe(EmptyFolderBehavior.Delete);
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
        // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
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
        specialCharacters: String.raw`#^[]|*\<>:?`,
        version: '9.15.0'
      });
      expect(component.settings.specialCharacters).toBe(String.raw`#^[]|*\<>:?/`);
    });

    it('should convert legacy moment-format tokens into the new format', async () => {
      const component = await createComponent({
        // eslint-disable-next-line no-template-curly-in-string -- Legacy token format.
        generatedAttachmentFileName: 'file-${date:YYYYMMDD}'
      });
      expect(component.settings.generatedAttachmentFileName).toBe('file-{{date:{momentJsFormat:\'YYYYMMDD\'}}}');
    });

    /* eslint-disable no-template-curly-in-string -- The retired `${...}` plugin token syntax, not JS template literals. */
    it('should migrate every tokenized setting from the ${...} syntax to {{...}}', async () => {
      const component = await createComponent({
        attachmentFolderPath: './assets/${noteFileName}/${date:{momentJsFormat:\'YYYY\'}}',
        collectedAttachmentFileName: 'collected-${sequenceNumber:{length:2}}',
        collectedAttachmentFolderPath: './${noteFileName}.assets',
        generatedAttachmentFileName: '${prompt:{defaultValueTemplate:\'${originalAttachmentFileName}-${date:{momentJsFormat:"YYYY"}}\'}}',
        markdownUrlFormat: '<${generatedAttachmentFilePath}>',
        renamedAttachmentFileName: '${noteFileName}-${originalAttachmentFileName}',
        version: '13.0.0'
      });
      expect(component.settings.attachmentFolderPath).toBe('./assets/{{noteFileName}}/{{date:{momentJsFormat:\'YYYY\'}}}');
      expect(component.settings.collectedAttachmentFileName).toBe('collected-{{sequenceNumber:{length:2}}}');
      expect(component.settings.collectedAttachmentFolderPath).toBe('./{{noteFileName}}.assets');
      expect(component.settings.generatedAttachmentFileName).toBe(
        '{{prompt:{defaultValueTemplate:\'{{originalAttachmentFileName}}-{{date:{momentJsFormat:"YYYY"}}}\'}}}'
      );
      expect(component.settings.markdownUrlFormat).toBe('<{{generatedAttachmentFilePath}}>');
      expect(component.settings.renamedAttachmentFileName).toBe('{{noteFileName}}-{{originalAttachmentFileName}}');
    });

    it('should carry the pre-10.0.0 scalar date format through both migrations', async () => {
      const component = await createComponent({
        attachmentFolderPath: 'assets/${noteFileCreationDate:YYYY}',
        version: '9.0.0'
      });
      expect(component.settings.attachmentFolderPath).toBe('assets/{{noteFileCreationDate:{momentJsFormat:\'YYYY\'}}}');
    });

    it('should not migrate the custom tokens code', async () => {
      const customTokensString = 'registerCustomToken(\'foo\', (ctx) => ctx.fillTemplate(\'${noteFileName}\'));';
      const component = await createComponent({
        // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key.
        customTokensStr: customTokensString,
        version: '13.0.0'
      });
      expect(component.settings.customTokensStr).toBe(customTokensString);
    });
    /* eslint-enable no-template-curly-in-string -- The retired `${...}` plugin token syntax, not JS template literals. */

    it('should leave a setting already in the {{...}} syntax as it is', async () => {
      const component = await createComponent({
        attachmentFolderPath: './assets/{{noteFileName}}',
        generatedAttachmentFileName: 'file-{{date:YYYY-MM-DD}}',
        version: '14.0.0'
      });
      expect(component.settings.attachmentFolderPath).toBe('./assets/{{noteFileName}}');
      expect(component.settings.generatedAttachmentFileName).toBe('file-{{date:YYYY-MM-DD}}');
    });

    it('should leave settings at defaults when no legacy keys are present', async () => {
      const component = await createComponent({});
      expect(component.settings.attachmentRenameMode).toBe(AttachmentRenameMode.OnlyPastedImages);
    });

    // A fresh install has none of the old keys, so it must never be told it has a migration waiting.
    it('should propose nothing when no rename/delete keys are present', async () => {
      const component = await createComponent({});
      expect(component.settings.proposedRenameDeleteSettings).toBeNull();
    });
  });
});
