import type { DataHandler } from '@mnaoumov/obsidian-lib/data-handler';
import type { PathOrAbstractFile } from '@mnaoumov/obsidian-lib/file-system';
import type { PluginEventSource } from '@mnaoumov/obsidian-lib/plugin/plugin-event-source';
import type { MaybeReturn } from '@mnaoumov/typescript-lib/type';
import type { ValueWrapper } from '@mnaoumov/typescript-lib/value-wrapper';

import { PluginSettingsComponentBase } from '@mnaoumov/obsidian-lib/components/plugin-settings-component';
import {
  getPath,
  isNote
} from '@mnaoumov/obsidian-lib/file-system';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { pathsValidator } from '@mnaoumov/obsidian-lib/path-settings';
import { getOsUnsafePathCharsRegExp } from '@mnaoumov/obsidian-lib/validation';
import { EmptyFolderBehavior } from '@mnaoumov/obsidian-lib/vault';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { isValidRegExp } from '@mnaoumov/typescript-lib/reg-exp';
import { replaceAll } from '@mnaoumov/typescript-lib/string';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';
import {
  App,
  debounce
} from 'obsidian';
import { compare } from 'semver';

import type { MigratableSettings } from '../advanced-rename-and-delete-handler/advanced-rename-and-delete-handler.ts';
import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';

import { CustomToken } from '../tokens/custom/custom-token.ts';
import { Substitutions } from '../tokens/substitutions.ts';
import { migrateLegacyTokenSyntax } from '../tokens/token-parser.ts';
import {
  TokenValidationMode,
  TokenValidator
} from '../tokens/token-validator.ts';
import {
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  PluginSettings,
  RenameAttachmentsCreatedByOtherPluginsMode
} from './plugin-settings.ts';

const CUSTOM_TOKENS_VALIDATOR_DEBOUNCE_IN_MILLISECONDS = 2000;
const EXCALIDRAW_EXTENSION = '.excalidraw.md';
const EXCALIDRAW_PROPERTY_ENTRY = 'property:excalidraw-plugin';

// Every setting evaluated as a template, so every one the `{{...}}` syntax migration rewrites.
const TOKENIZED_SETTINGS_KEYS = [
  'attachmentFolderPath',
  'collectedAttachmentFileName',
  'collectedAttachmentFolderPath',
  'generatedAttachmentFileName',
  'insertedLinkText',
  'markdownUrlFormat',
  'renamedAttachmentFileName'
] as const satisfies readonly (keyof PluginSettings)[];

interface AddDateTimeFormatParams {
  readonly $string: string;
  readonly dateTimeFormat: string;
}

interface PluginSettingsComponentConstructorParams {
  readonly app: App;
  readonly dataHandler: DataHandler;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly pluginEventSource: PluginEventSource;
  readonly validatorWrapper: ValueWrapper<TokenValidator>;
}

class LegacySettings {
  public autoRenameFiles = false;
  public autoRenameFolder = true;
  /**
   * Obsolete legacy setting that is not converted. Declared so the legacy-settings converter
   * recognizes the persisted key and strips it from saved settings during migration.
   */
  public convertImagesOnDragAndDrop = false;
  public convertImagesToJpeg = false;
  public dateTimeFormat = '';
  // eslint-disable-next-line unicorn/no-non-function-verb-prefix -- A legacy persisted settings key; renaming it would break migration from every existing `data.json`.
  public deleteOrphanAttachments = false;
  public emptyAttachmentFolderBehavior = EmptyFolderBehavior.DeleteWithEmptyParents;
  /*
   * The rename/delete settings this plugin owned before 12.0.0. They are no longer members of
   * `PluginSettings` — `Advanced Rename and Delete Handler` owns them now — but they are still declared here
   * for the two reasons this class exists: so the converter recognizes the persisted keys and strips them
   * from saved settings, and so `convertRenameDeleteSettingsToProposal` can gather the user's values into
   * `proposedRenameDeleteSettings` instead of silently dropping them.
   */
  public emptyFolderBehavior = EmptyFolderBehavior.DeleteWithEmptyParents;
  public excludePaths: readonly string[] = [];
  public generatedAttachmentFilename = '';
  public includePaths: readonly string[] = [];
  public keepEmptyAttachmentFolders = false;
  public notePriorities: readonly string[] = [];
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  public pastedFileName = 'file-${date:YYYYMMDDHHmmssSSS}';
  public pastedImageFileName = '';
  /**
   * Obsolete legacy setting that is not converted. Declared so the legacy-settings converter
   * recognizes the persisted key and strips it from saved settings during migration.
   */
  public renameAttachmentsOnDragAndDrop = false;
  public renameCollectedFiles = false;
  /**
   * Obsolete legacy setting that is not converted. Declared so the legacy-settings converter
   * recognizes the persisted key and strips it from saved settings during migration.
   */
  public renameOnlyImages = false;
  /**
   * Obsolete legacy setting that is not converted. Declared so the legacy-settings converter
   * recognizes the persisted key and strips it from saved settings during migration.
   */
  public renamePastedFilesWithKnownNames = false;
  public replaceWhitespace = false;
  public shouldConvertPastedImagesToJpeg = false;
  public shouldDeleteOrphanAttachments = false;
  public shouldDuplicateCollectedAttachments = false;
  public shouldHandleRenames = true;
  public shouldKeepEmptyAttachmentFolders = false;
  public shouldRenameAttachmentFiles = false;
  public shouldRenameAttachmentFolder = true;
  public shouldRenameAttachments = true;
  /**
   * The all-or-nothing switch that `renameAttachmentsCreatedByOtherPluginsMode` replaced in 12.1.0, when
   * issue #77 asked for the rename to be scoped to named plugins.
   */
  public shouldRenameAttachmentsCreatedByOtherPlugins = false;
  /**
   * Obsolete legacy setting that is not converted. Declared so the legacy-settings converter
   * recognizes the persisted key and strips it from saved settings during migration.
   */
  public shouldRenameAttachmentsToLowerCase = false;
  public shouldRescueSharedAttachments = false;
  /**
   * Obsolete legacy setting that is not converted. Declared so the legacy-settings converter
   * recognizes the persisted key and strips it from saved settings during migration.
   */
  public toLowerCase = false;
  public treatAsAttachmentExtensions: readonly string[] = ['.excalidraw.md'];
  public warningVersion = '';
  public whitespaceReplacement = '';
}

class LegacySettingsConverter {
  public constructor(private readonly legacySettings: Partial<LegacySettings> & Partial<PluginSettings>) {}

  public convert(): void {
    this.convertWarningVersion();

    this.convertDateTimeFormat();
    this.convertReplaceWhitespace();
    this.convertAutoRenameFiles();
    this.convertAutoRenameFolder();
    this.convertShouldRenameAttachments();
    this.convertDeleteOrphanAttachments();
    this.convertKeepEmptyAttachmentFolders();
    this.convertRenameCollectedFiles();
    this.convertCustomTokensString();
    this.convertConvertImagesToJpeg();
    this.convertWhitespaceReplacement();
    this.convertShouldKeepEmptyAttachmentFolders();
    this.convertCollectAttachmentUsedByMultipleNotesMode();
    this.convertRenameAttachmentsCreatedByOtherPluginsMode();
    this.convertMarkdownUrlFormat();
    this.convertSpecialCharacters();
    this.convertLegacyTokens();
    // After every converter above, since several of them still write the `${...}` syntax.
    this.convertTokenSyntax();

    // LAST, and it must stay last: it reads the rename/delete keys the converters above normalize, so
    // running it earlier would gather the raw legacy names instead of the values they convert into.
    this.convertRenameDeleteSettingsToProposal();
  }

  private convertAutoRenameFiles(): void {
    if (this.legacySettings.autoRenameFiles !== undefined) {
      this.legacySettings.shouldRenameAttachmentFiles = this.legacySettings.autoRenameFiles;
    }
  }

  private convertAutoRenameFolder(): void {
    if (this.legacySettings.autoRenameFolder !== undefined) {
      this.legacySettings.shouldRenameAttachmentFolder = this.legacySettings.autoRenameFolder;
    }
  }

  private convertCollectAttachmentUsedByMultipleNotesMode(): void {
    if (this.legacySettings.collectAttachmentUsedByMultipleNotesMode === undefined && this.legacySettings.shouldDuplicateCollectedAttachments !== undefined) {
      this.legacySettings.collectAttachmentUsedByMultipleNotesMode = this.legacySettings.shouldDuplicateCollectedAttachments
        ? CollectAttachmentUsedByMultipleNotesMode.Copy
        : CollectAttachmentUsedByMultipleNotesMode.Skip;
    }
  }

  private convertConvertImagesToJpeg(): void {
    if (this.legacySettings.shouldConvertPastedImagesToJpeg !== undefined || this.legacySettings.convertImagesToJpeg !== undefined) {
      this.legacySettings.convertImagesToJpegMode = this.legacySettings.shouldConvertPastedImagesToJpeg ?? this.legacySettings.convertImagesToJpeg
        ? ConvertImagesToJpegMode.OnlyPastedClipboardPngImages
        : ConvertImagesToJpegMode.None;
    }
  }

  private convertCustomTokensString(): void {
    if (this.legacySettings.customTokensStr && this.legacySettings.version && compare(this.legacySettings.version, '9.0.0') < 0) {
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
      this.legacySettings.customTokensStr = `${t(($) => $.pluginSettingsManager.customToken.codeComment)}

${commentOut(this.legacySettings.customTokensStr)}
`;
    }
  }

  private convertDateTimeFormat(): void {
    const dateTimeFormat = this.legacySettings.dateTimeFormat ?? 'YYYYMMDDHHmmssSSS';
    // An absent key stays absent, so the default fills it. Converting it to '' used to put the attachments of
    // any record written without this key, such as a hand-seeded `data.json`, at the vault root.
    if (this.legacySettings.attachmentFolderPath !== undefined) {
      this.legacySettings.attachmentFolderPath = addDateTimeFormat({ $string: this.legacySettings.attachmentFolderPath, dateTimeFormat });
    }

    this.legacySettings.generatedAttachmentFileName = addDateTimeFormat({
      $string: this.legacySettings.generatedAttachmentFileName
        ?? this.legacySettings.generatedAttachmentFilename
        ?? this.legacySettings.pastedFileName
        ?? this.legacySettings.pastedImageFileName
        // eslint-disable-next-line no-template-curly-in-string -- Valid token.
        ?? 'file-${date}',
      dateTimeFormat
    });
  }

  private convertDeleteOrphanAttachments(): void {
    if (this.legacySettings.deleteOrphanAttachments !== undefined) {
      this.legacySettings.shouldDeleteOrphanAttachments = this.legacySettings.deleteOrphanAttachments;
    }
  }

  private convertKeepEmptyAttachmentFolders(): void {
    if (this.legacySettings.keepEmptyAttachmentFolders !== undefined) {
      this.legacySettings.shouldKeepEmptyAttachmentFolders = this.legacySettings.keepEmptyAttachmentFolders;
    }
  }

  private convertLegacyTokens(): void {
    if (this.legacySettings.attachmentFolderPath !== undefined) {
      this.legacySettings.attachmentFolderPath = this.replaceLegacyTokens(this.legacySettings.attachmentFolderPath);
    }

    // Never absent here: `convertDateTimeFormat` falls back to a pattern when the record has none.
    this.legacySettings.generatedAttachmentFileName = this.replaceLegacyTokens(ensureNonNullable(this.legacySettings.generatedAttachmentFileName));
    // An absent key stays absent, so the default fills it rather than an '' that happens to match it today.
    if (this.legacySettings.markdownUrlFormat !== undefined) {
      this.legacySettings.markdownUrlFormat = this.replaceLegacyTokens(this.legacySettings.markdownUrlFormat);
    }
  }

  private convertMarkdownUrlFormat(): void {
    if (
      this.legacySettings.version && compare(this.legacySettings.version, '9.2.0') < 0
      // eslint-disable-next-line no-template-curly-in-string -- Valid token.
      && (this.legacySettings.markdownUrlFormat === '${generatedAttachmentFilePath}' || this.legacySettings.markdownUrlFormat === '${noteFilePath}')
    ) {
      this.legacySettings.markdownUrlFormat = '';
    }
  }

  /**
   * Carries the pre-12.1.0 all-or-nothing switch onto the mode that replaced it.
   *
   * `true` becomes `All`, which is exactly what the switch meant; `false` becomes `None`. Neither list mode
   * can be reached from the old value, since the old setting had no list to name.
   */
  private convertRenameAttachmentsCreatedByOtherPluginsMode(): void {
    if (
      this.legacySettings.renameAttachmentsCreatedByOtherPluginsMode === undefined
      && this.legacySettings.shouldRenameAttachmentsCreatedByOtherPlugins !== undefined
    ) {
      this.legacySettings.renameAttachmentsCreatedByOtherPluginsMode = this.legacySettings.shouldRenameAttachmentsCreatedByOtherPlugins
        ? RenameAttachmentsCreatedByOtherPluginsMode.All
        : RenameAttachmentsCreatedByOtherPluginsMode.None;
    }
  }

  private convertRenameCollectedFiles(): void {
    if (this.legacySettings.renameCollectedFiles !== undefined) {
      this.legacySettings.shouldRenameCollectedAttachments = this.legacySettings.renameCollectedFiles;
    }
  }

  /**
   * Gathers the rename/delete values this plugin used to own into a proposal for
   * `Advanced Rename and Delete Handler`.
   *
   * Only keys the user actually had are gathered. A fresh install has none of them, so the proposal stays
   * `null` and nobody is offered a migration of values they never set — which is the whole reason this is one
   * nullable object rather than a flag beside a set of defaults.
   *
   * `shouldDeleteOrphanAttachments` is the one rename: the other plugin spells the same setting
   * `shouldHandleDeletions`.
   */
  private convertRenameDeleteSettingsToProposal(): void {
    const legacySettings = this.legacySettings;
    const proposedSettings: Record<string, unknown> = {};

    function copyIfPresent(targetPropertyName: string, value: unknown): void {
      if (value !== undefined) {
        proposedSettings[targetPropertyName] = value;
      }
    }

    copyIfPresent('emptyFolderBehavior', legacySettings.emptyFolderBehavior);
    copyIfPresent('excludePaths', legacySettings.excludePaths);
    copyIfPresent('includePaths', legacySettings.includePaths);
    copyIfPresent('notePriorities', legacySettings.notePriorities);
    copyIfPresent('shouldHandleDeletions', legacySettings.shouldDeleteOrphanAttachments);
    copyIfPresent('shouldHandleRenames', legacySettings.shouldHandleRenames);
    copyIfPresent('shouldRenameAttachmentFiles', legacySettings.shouldRenameAttachmentFiles);
    copyIfPresent('shouldRenameAttachmentFolder', legacySettings.shouldRenameAttachmentFolder);
    copyIfPresent('shouldRescueSharedAttachments', legacySettings.shouldRescueSharedAttachments);
    copyIfPresent('treatAsAttachmentExtensions', addExcalidrawPropertyEntry(legacySettings.treatAsAttachmentExtensions));

    if (Object.keys(proposedSettings).length === 0) {
      return;
    }

    this.legacySettings.proposedRenameDeleteSettings = castTo<MigratableSettings>(proposedSettings);
  }

  private convertReplaceWhitespace(): void {
    if (this.legacySettings.replaceWhitespace !== undefined) {
      this.legacySettings.whitespaceReplacement = this.legacySettings.replaceWhitespace ? '-' : '';
    }
  }

  private convertShouldKeepEmptyAttachmentFolders(): void {
    if (this.legacySettings.shouldKeepEmptyAttachmentFolders !== undefined) {
      this.legacySettings.emptyFolderBehavior = this.legacySettings.shouldKeepEmptyAttachmentFolders
        ? EmptyFolderBehavior.Keep
        : EmptyFolderBehavior.DeleteWithEmptyParents;
    }

    if (this.legacySettings.emptyAttachmentFolderBehavior !== undefined) {
      this.legacySettings.emptyFolderBehavior = this.legacySettings.emptyAttachmentFolderBehavior;
    }
  }

  private convertShouldRenameAttachments(): void {
    if (this.legacySettings.shouldRenameAttachments !== undefined) {
      this.legacySettings.shouldRenameAttachmentFolder = this.legacySettings.shouldRenameAttachments;
    }
  }

  private convertSpecialCharacters(): void {
    if (this.legacySettings.version && compare(this.legacySettings.version, '9.16.0') < 0 && this.legacySettings.specialCharacters === String.raw`#^[]|*\<>:?`) {
      this.legacySettings.specialCharacters = String.raw`#^[]|*\<>:?/`;
    }
  }

  /**
   * Carries tokenized settings from the retired `${...}` syntax onto `{{...}}` (14.0.0).
   *
   * Not version-gated, deliberately: `${...}` no longer parses, so a legacy token left in any of these keys is
   * broken whatever version wrote it, and {@link migrateLegacyTokenSyntax} leaves a string holding none untouched.
   * `customTokensStr` is user-authored JavaScript and is NOT migrated; a template it still fills in the old syntax
   * fails with a `LegacyTokenSyntaxError` naming the replacement.
   */
  private convertTokenSyntax(): void {
    for (const key of TOKENIZED_SETTINGS_KEYS) {
      const value = this.legacySettings[key];
      if (typeof value === 'string') {
        this.legacySettings[key] = migrateLegacyTokenSyntax(value);
      }
    }
  }

  private convertWarningVersion(): void {
    if (this.legacySettings.warningVersion !== undefined) {
      this.legacySettings.version = this.legacySettings.warningVersion;
    }
  }

  private convertWhitespaceReplacement(): void {
    if (!this.legacySettings.whitespaceReplacement) {
      return;
    }

    this.legacySettings.specialCharacters = `${this.legacySettings.specialCharacters ?? ''} `;
    this.legacySettings.specialCharactersReplacement = this.legacySettings.whitespaceReplacement;
  }

  private replaceLegacyTokens($string: string): string {
    return replaceAll({
      $string,
      replacer: ({ capturedGroupArguments: [token, momentJsFormat] }) => {
        return `\${${ensureNonNullable(token)}:{momentJsFormat:'${ensureNonNullable(momentJsFormat)}'}}`;
      },
      searchValue: /\$\{(?<Token>date|noteFileCreationDate|noteFileModificationDate|originalAttachmentFileCreationDate|originalAttachmentFileModificationDate):(?<MomentJsFormat>\s*[^{]+?)\}/gi
    });
  }
}

export class PluginSettingsComponent extends PluginSettingsComponentBase<PluginSettings> {
  public shouldDebounceCustomTokensValidation = false;

  private readonly app: App;

  private readonly customTokensValidatorDebounced = debounce(this.customTokensValidatorImpl.bind(this), CUSTOM_TOKENS_VALIDATOR_DEBOUNCE_IN_MILLISECONDS);

  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;

  private lastCustomTokenValidatorResult: string | undefined = undefined;

  private readonly validatorWrapper: ValueWrapper<TokenValidator>;

  private get validator(): TokenValidator {
    return this.validatorWrapper.value;
  }

  public constructor(params: PluginSettingsComponentConstructorParams) {
    super({
      ...params,
      pluginSettingsClass: PluginSettings
    });
    this.app = params.app;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.validatorWrapper = params.validatorWrapper;
  }

  /**
   * Whether a file is a note rather than an attachment.
   *
   * The attachment-extension list this consults belongs to `Advanced Rename and Delete Handler` since 12.0.0,
   * so it is read back rather than held here. It is the same question in both plugins — "is this
   * `.excalidraw.md` a note or a drawing?" — so a single answer is the right one.
   *
   * @param pathOrFile - The path or file to test.
   * @returns Whether it counts as a note.
   */
  public isNoteEx(pathOrFile: null | PathOrAbstractFile): boolean {
    if (!pathOrFile || !isNote(pathOrFile)) {
      return false;
    }

    const path = getPath(this.app, pathOrFile);
    return !this.handedOverSettingsComponent.isTreatedAsAttachment(path);
  }

  public replaceSpecialCharacters($string: string): string {
    if (!this.settings.specialCharacters) {
      return $string;
    }

    $string = $string.replace(this.settings.specialCharactersRegExp, () => this.settings.specialCharactersReplacement);
    return $string;
  }

  /**
   * Registers the custom tokens the settings define, then validates them.
   *
   * The library validates every load and every edit here, before it saves or raises an event, so this is the one
   * hook that reaches a template naming a token saved in the SAME edit: a `data.json` replaced by sync, or an
   * `editAndSave` from a script. Every validation in this plugin is of the record about to become the settings.
   *
   * Skipped while the settings tab debounces custom-token validation, since it then registers them itself, and
   * running half-typed code on every keystroke is what that debounce exists to avoid.
   *
   * @param settings - The settings.
   * @returns The validation result.
   */
  public override async validate(settings: PluginSettings): ReturnType<PluginSettingsComponentBase<PluginSettings>['validate']> {
    if (!this.shouldDebounceCustomTokensValidation) {
      Substitutions.ensureCustomTokensRegistered(settings.customTokensStr);
    }

    return await super.validate(settings);
  }

  protected override registerLegacySettingsConverters(): void {
    this.registerLegacySettingsConverter(LegacySettings, (legacySettings) => {
      new LegacySettingsConverter(legacySettings).convert();
    });
  }

  protected override registerValidators(): void {
    this.registerValidator('insertedLinkText', async (value) => await this.validator.validateTokens(value) ?? undefined);
    this.registerValidator('attachmentFolderPath', async (value) =>
      await this.validator.validatePath({
        areTokensAllowed: true,
        path: value
      }));
    // Empty is legal here and means "use `attachmentFolderPath`"; `validatePath` already passes an empty path.
    this.registerValidator('collectedAttachmentFolderPath', async (value) =>
      await this.validator.validatePath({
        areTokensAllowed: true,
        path: value
      }));
    this.registerValidator('generatedAttachmentFileName', async (value) =>
      await this.validator.validatePath({
        areTokensAllowed: true,
        path: value
      }));

    this.registerValidator('specialCharactersReplacement', (value): MaybeReturn<string> => {
      if (getOsUnsafePathCharsRegExp().test(value)) {
        return t(($) => $.pluginSettingsManager.validation.specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters);
      }
    });

    this.registerValidator('defaultImageSize', (value): MaybeReturn<string> => {
      const REG_EXP = /^(?:\d+(?:px|%))?$/g;
      if (!REG_EXP.test(value)) {
        return t(($) => $.pluginSettingsManager.validation.defaultImageSizeMustBePercentageOrPixels);
      }
    });

    this.registerValidator('duplicateNameSeparator', async (value): Promise<MaybeReturn<string>> => {
      return await this.validator.validateFileName({
        areSingleDotsAllowed: false,
        fileName: `foo${value}1`,
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Error
      });
    });

    this.registerValidator('excludeExtensionsFromMultipleNotesCheck', (value): MaybeReturn<string> => {
      return extensionsValidator(value);
    });
    this.registerValidator('sidecarExtensions', (value): MaybeReturn<string> => extensionsValidator(value));

    // The vault path lists are `PathSettings`, so the library that matches them is the one that says which entries are valid.
    this.registerValidator('attachmentUnitFolderPaths', (value): MaybeReturn<string> => {
      return pathsValidator(value);
    });

    this.registerValidator('excludePathsFromAttachmentCollecting', (value): MaybeReturn<string> => {
      return pathsValidator(value);
    });

    this.registerValidator('excludePathsFromMultipleNotesCheck', (value): MaybeReturn<string> => {
      return pathsValidator(value);
    });

    this.registerValidator('orphanAttachmentScanPaths', (value): MaybeReturn<string> => {
      return pathsValidator(value);
    });

    this.registerValidator('screenshotFilePaths', (value): MaybeReturn<string> => {
      return screenshotFilePathsValidator(value);
    });

    this.registerValidator('customTokensStr', (value): MaybeReturn<string> => {
      return this.customTokensValidator(value);
    });
  }

  private customTokensValidator(customTokensString: string): MaybeReturn<string> {
    if (this.shouldDebounceCustomTokensValidation) {
      this.customTokensValidatorDebounced(customTokensString);
    } else {
      this.customTokensValidatorImpl(customTokensString);
    }

    return this.lastCustomTokenValidatorResult ?? undefined;
  }

  private customTokensValidatorImpl(customTokensString: string): void {
    const customTokens = CustomToken.parse(customTokensString);
    this.lastCustomTokenValidatorResult = customTokens === null ? t(($) => $.pluginSettingsManager.validation.invalidCustomTokensCode) : undefined;
  }
}

function addDateTimeFormat(params: AddDateTimeFormatParams): string {
  const { $string, dateTimeFormat } = params;
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  return $string.replaceAll('${date}', () => `\${date:{momentJsFormat:'${dateTimeFormat}'}}`);
}

/**
 * Carries a historic `treatAsAttachmentExtensions` list over to `Advanced Rename and Delete Handler` without losing
 * what that plugin now adds to it (#90).
 *
 * This plugin's list could only hold extensions, so a user who kept `.excalidraw.md` in it meant "an `Excalidraw`
 * drawing is an attachment". The handler says the same thing since 2.1.0 with a second entry,
 * `property:excalidraw-plugin`, which also catches a drawing saved as a plain `.md`. Proposed as it was, the
 * historic list would show up as a row that REMOVES that entry from the handler's default, and a user approving it
 * would lose the new behavior without being told. A list without `.excalidraw.md` is a user who opted out of
 * treating drawings as attachments, and is proposed unchanged.
 *
 * @param extensions - The historic list, or `undefined` when the user never saved one.
 * @returns The list to propose.
 */
function addExcalidrawPropertyEntry(extensions: readonly string[] | undefined): readonly string[] | undefined {
  const shouldAdd = extensions?.includes(EXCALIDRAW_EXTENSION) === true && !extensions.includes(EXCALIDRAW_PROPERTY_ENTRY);
  return shouldAdd ? [...extensions, EXCALIDRAW_PROPERTY_ENTRY] : extensions;
}

function commentOut($string: string): string {
  return $string.replaceAll(/^/gm, '// ');
}

/**
 * Rejects the one mistake the extension list cannot absorb: a PATH typed into it.
 *
 * Everything else an entry can be is already handled silently by
 * {@link PluginSettings.isExtensionExcludedFromMultipleNotesCheck} - a leading dot, any casing, a blank line. A path
 * is different, because it would simply never match anything and the user would be left believing the setting is
 * broken. The two settings sit next to each other in the tab and the other one is the one that wants paths, so this
 * is the mistake worth naming.
 *
 * @param extensions - The raw entries as typed.
 * @returns The validation message, or nothing when every entry is usable.
 */
function extensionsValidator(extensions: string[]): MaybeReturn<string> {
  for (const extension of extensions) {
    if (/[/\\]/.test(extension)) {
      return t(($) => $.pluginSettingsManager.validation.multipleNotesCheckExtensionMustNotBeAPath, { extension });
    }
  }
}

/**
 * Rejects an invalid regular expression in {@link PluginSettings.screenshotFilePaths}.
 *
 * That list holds operating-system paths and is matched by `isScreenshotFilePath`, not by `PathSettings`, so it keeps
 * its own two forms - a folder, or an entry wrapped in `/` - and the library's validator does not apply to it.
 *
 * @param paths - The raw entries as typed.
 * @returns The validation message, or nothing when every entry is usable.
 */
function screenshotFilePathsValidator(paths: string[]): MaybeReturn<string> {
  for (const path of paths) {
    if (!(path.startsWith('/') && path.endsWith('/'))) {
      continue;
    }

    const regExp = path.slice(1, -1);
    if (!isValidRegExp(regExp)) {
      return t(($) => $.pluginSettingsManager.validation.invalidRegularExpression, { regExp: path });
    }
  }
}
