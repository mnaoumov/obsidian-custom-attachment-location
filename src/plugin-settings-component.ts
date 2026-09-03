import type { DataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import type { PathOrAbstractFile } from 'obsidian-dev-utils/obsidian/file-system';
import type { PluginEventSource } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';
import type { MaybeReturn } from 'obsidian-dev-utils/type';
import type { ValueWrapper } from 'obsidian-dev-utils/value-wrapper';

import {
  App,
  debounce
} from 'obsidian';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { PluginSettingsComponentBase } from 'obsidian-dev-utils/obsidian/components/plugin-settings-component';
import {
  getPath,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { getOsUnsafePathCharsRegExp } from 'obsidian-dev-utils/obsidian/validation';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/vault';
import { isValidRegExp } from 'obsidian-dev-utils/reg-exp';
import { replaceAll } from 'obsidian-dev-utils/string';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';
import { compare } from 'semver';

import type { MigratableSettings } from './advanced-rename-and-delete-handler.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';

import {
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  PluginSettings,
  RenameAttachmentsCreatedByOtherPluginsMode
} from './plugin-settings.ts';
import {
  TokenValidationMode,
  TokenValidator
} from './token-validator.ts';
import { CustomToken } from './tokens/custom-token.ts';

const CUSTOM_TOKENS_VALIDATOR_DEBOUNCE_IN_MILLISECONDS = 2000;

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
   * `PluginSettings` — Advanced Rename and Delete Handler owns them now — but they are still declared here
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

    // LAST, and it must stay last: it reads the rename/delete keys the converters above normalize, so
    // Running it earlier would gather the raw legacy names instead of the values they convert into.
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
    this.legacySettings.attachmentFolderPath = addDateTimeFormat({ $string: this.legacySettings.attachmentFolderPath ?? '', dateTimeFormat });

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
    this.legacySettings.attachmentFolderPath = this.replaceLegacyTokens(this.legacySettings.attachmentFolderPath);
    this.legacySettings.generatedAttachmentFileName = this.replaceLegacyTokens(this.legacySettings.generatedAttachmentFileName);
    this.legacySettings.markdownUrlFormat = this.replaceLegacyTokens(this.legacySettings.markdownUrlFormat);
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
   * Gathers the rename/delete values this plugin used to own into a proposal for Advanced Rename and Delete
   * Handler.
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
    copyIfPresent('treatAsAttachmentExtensions', legacySettings.treatAsAttachmentExtensions);

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

  private replaceLegacyTokens($string: string | undefined): string {
    if ($string === undefined) {
      return '';
    }

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
   * The attachment-extension list this consults belongs to Advanced Rename and Delete Handler since 12.0.0,
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

  protected override registerLegacySettingsConverters(): void {
    this.registerLegacySettingsConverter(LegacySettings, (legacySettings) => {
      new LegacySettingsConverter(legacySettings).convert();
    });
  }

  protected override registerValidators(): void {
    this.registerValidator('attachmentFolderPath', async (value) =>
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

    this.registerValidator('excludePathsFromMultipleNotesCheck', (value): MaybeReturn<string> => {
      return pathsValidator(value);
    });

    this.registerValidator('orphanAttachmentScanPaths', (value): MaybeReturn<string> => {
      return pathsValidator(value);
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

function commentOut($string: string): string {
  return $string.replaceAll(/^/gm, '// ');
}

function pathsValidator(paths: string[]): MaybeReturn<string> {
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
