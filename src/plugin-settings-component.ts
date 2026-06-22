import type { DataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import type { PathOrAbstractFile } from 'obsidian-dev-utils/obsidian/file-system';
import type { PluginEventSource } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';
import type { MaybeReturn } from 'obsidian-dev-utils/type';
import type { ValueWrapper } from 'obsidian-dev-utils/value-wrapper';

import {
  App,
  debounce
} from 'obsidian';
import { PluginSettingsComponentBase } from 'obsidian-dev-utils/obsidian/components/plugin-settings-component';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import {
  getPath,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { getOsUnsafePathCharsRegExp } from 'obsidian-dev-utils/obsidian/validation';
import { isValidRegExp } from 'obsidian-dev-utils/reg-exp';
import { replaceAll } from 'obsidian-dev-utils/string';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';
import { compare } from 'semver';

import {
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  PluginSettings
} from './plugin-settings.ts';
import {
  parseCustomTokens,
  TokenValidationMode,
  Validator
} from './substitutions.ts';

const CUSTOM_TOKENS_VALIDATOR_DEBOUNCE_IN_MILLISECONDS = 2000;

interface PluginSettingsComponentConstructorParams {
  readonly app: App;
  readonly dataHandler: DataHandler;
  readonly pluginEventSource: PluginEventSource;
  readonly validatorWrapper: ValueWrapper<Validator>;
}

class LegacySettings {
  public autoRenameFiles = false;
  public autoRenameFolder = true;
  public convertImagesOnDragAndDrop = false;
  public convertImagesToJpeg = false;
  public dateTimeFormat = '';
  public deleteOrphanAttachments = false;
  public emptyAttachmentFolderBehavior = EmptyFolderBehavior.DeleteWithEmptyParents;
  public generatedAttachmentFilename = '';
  public keepEmptyAttachmentFolders = false;
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  public pastedFileName = 'file-${date:YYYYMMDDHHmmssSSS}';
  public pastedImageFileName = '';
  public renameAttachmentsOnDragAndDrop = false;
  public renameCollectedFiles = false;
  public renameOnlyImages = false;
  public renamePastedFilesWithKnownNames = false;
  public replaceWhitespace = false;
  public shouldConvertPastedImagesToJpeg = false;
  public shouldDuplicateCollectedAttachments = false;
  public shouldKeepEmptyAttachmentFolders = false;
  public shouldRenameAttachments = true;
  public shouldRenameAttachmentsToLowerCase = false;
  public toLowerCase = false;
  public warningVersion = '';
  public whitespaceReplacement = '';
}

class LegacySettingsConverter {
  public constructor(private readonly legacySettings: Partial<LegacySettings> & Partial<PluginSettings>) {
  }

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
    this.convertCustomTokensStr();
    this.convertConvertImagesToJpeg();
    this.convertWhitespaceReplacement();
    this.convertShouldKeepEmptyAttachmentFolders();
    this.convertCollectAttachmentUsedByMultipleNotesMode();
    this.convertMarkdownUrlFormat();
    this.convertSpecialCharacters();
    this.convertLegacyTokens();
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

  private convertCustomTokensStr(): void {
    if (this.legacySettings.customTokensStr && this.legacySettings.version && compare(this.legacySettings.version, '9.0.0') < 0) {
      this.legacySettings.customTokensStr = `${t(($) => $.pluginSettingsManager.customToken.codeComment)}

${commentOut(this.legacySettings.customTokensStr)}
`;
    }
  }

  private convertDateTimeFormat(): void {
    const dateTimeFormat = this.legacySettings.dateTimeFormat ?? 'YYYYMMDDHHmmssSSS';
    this.legacySettings.attachmentFolderPath = addDateTimeFormat(this.legacySettings.attachmentFolderPath ?? '', dateTimeFormat);

    this.legacySettings.generatedAttachmentFileName = addDateTimeFormat(
      this.legacySettings.generatedAttachmentFileName
        ?? this.legacySettings.generatedAttachmentFilename
        ?? this.legacySettings.pastedFileName
        ?? this.legacySettings.pastedImageFileName
        // eslint-disable-next-line no-template-curly-in-string -- Valid token.
        ?? 'file-${date}',
      dateTimeFormat
    );
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

  private convertRenameCollectedFiles(): void {
    if (this.legacySettings.renameCollectedFiles !== undefined) {
      this.legacySettings.shouldRenameCollectedAttachments = this.legacySettings.renameCollectedFiles;
    }
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
    if (this.legacySettings.version && compare(this.legacySettings.version, '9.16.0') < 0 && this.legacySettings.specialCharacters === '#^[]|*\\<>:?') {
      this.legacySettings.specialCharacters = '#^[]|*\\<>:?/';
    }
  }

  private convertWarningVersion(): void {
    if (this.legacySettings.warningVersion !== undefined) {
      this.legacySettings.version = this.legacySettings.warningVersion;
    }
  }

  private convertWhitespaceReplacement(): void {
    if (this.legacySettings.whitespaceReplacement) {
      this.legacySettings.specialCharacters = `${this.legacySettings.specialCharacters ?? ''} `;
      this.legacySettings.specialCharactersReplacement = this.legacySettings.whitespaceReplacement;
    }
  }

  private replaceLegacyTokens(str: string | undefined): string {
    if (str === undefined) {
      return '';
    }

    return replaceAll(
      str,
      /\$\{(?<Token>date|noteFileCreationDate|noteFileModificationDate|originalAttachmentFileCreationDate|originalAttachmentFileModificationDate):(?<MomentJsFormat>\s*[^{]+?)\}/gi,
      ({ capturedGroupArgs: [token, momentJsFormat] }) => {
        return `\${${ensureNonNullable(token)}:{momentJsFormat:'${ensureNonNullable(momentJsFormat)}'}}`;
      }
    );
  }
}

export class PluginSettingsComponent extends PluginSettingsComponentBase<PluginSettings> {
  public shouldDebounceCustomTokensValidation = false;

  private readonly app: App;

  private readonly customTokensValidatorDebounced = debounce(this.customTokensValidatorImpl.bind(this), CUSTOM_TOKENS_VALIDATOR_DEBOUNCE_IN_MILLISECONDS);

  private lastCustomTokenValidatorResult: string | undefined = undefined;

  private readonly validatorWrapper: ValueWrapper<Validator>;

  private get validator(): Validator {
    return this.validatorWrapper.value;
  }

  public constructor(params: PluginSettingsComponentConstructorParams) {
    super({
      ...params,
      pluginSettingsClass: PluginSettings
    });
    this.app = params.app;
    this.validatorWrapper = params.validatorWrapper;
  }

  public isNoteEx(pathOrFile: null | PathOrAbstractFile): boolean {
    if (!pathOrFile || !isNote(this.app, pathOrFile)) {
      return false;
    }

    const path = getPath(this.app, pathOrFile);
    return this.settings.treatAsAttachmentExtensions.every((extension) => !path.endsWith(extension));
  }

  public replaceSpecialCharacters(str: string): string {
    if (!this.settings.specialCharacters) {
      return str;
    }

    str = str.replace(this.settings.specialCharactersRegExp, this.settings.specialCharactersReplacement);
    return str;
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
      if (getOsUnsafePathCharsRegExp().exec(value)) {
        return t(($) => $.pluginSettingsManager.validation.specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters);
      }
    });

    this.registerValidator('defaultImageSize', (value): MaybeReturn<string> => {
      const REG_EXP = /^(?:\d+(?:px|%))?$/g;
      if (!REG_EXP.exec(value)) {
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

    this.registerValidator('includePaths', (value): MaybeReturn<string> => {
      return pathsValidator(value);
    });

    this.registerValidator('excludePaths', (value): MaybeReturn<string> => {
      return pathsValidator(value);
    });

    this.registerValidator('customTokensStr', (value): MaybeReturn<string> => {
      return this.customTokensValidator(value);
    });
  }

  private customTokensValidator(customTokensStr: string): MaybeReturn<string> {
    if (this.shouldDebounceCustomTokensValidation) {
      this.customTokensValidatorDebounced(customTokensStr);
    } else {
      this.customTokensValidatorImpl(customTokensStr);
    }

    return this.lastCustomTokenValidatorResult ?? undefined;
  }

  private customTokensValidatorImpl(customTokensStr: string): void {
    const customTokens = parseCustomTokens(customTokensStr);
    this.lastCustomTokenValidatorResult = customTokens === null ? t(($) => $.pluginSettingsManager.validation.invalidCustomTokensCode) : undefined;
  }
}

function addDateTimeFormat(str: string, dateTimeFormat: string): string {
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  return str.replaceAll('${date}', `\${date:{momentJsFormat:'${dateTimeFormat}'}}`);
}

function commentOut(str: string): string {
  return str.replaceAll(/^/gm, '// ');
}

function pathsValidator(paths: string[]): MaybeReturn<string> {
  for (const path of paths) {
    if (path.startsWith('/') && path.endsWith('/')) {
      const regExp = path.slice(1, -1);
      if (!isValidRegExp(regExp)) {
        return t(($) => $.pluginSettingsManager.validation.invalidRegularExpression, { regExp: path });
      }
    }
  }
}
