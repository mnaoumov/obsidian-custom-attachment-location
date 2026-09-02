import { INFINITE_TIMEOUT } from 'obsidian-dev-utils/abort-controller';
import { PathSettings } from 'obsidian-dev-utils/obsidian/path-settings';
import { escapeRegExp } from 'obsidian-dev-utils/reg-exp';

import type { MigratableSettings } from './advanced-rename-and-delete-handler.ts';

export const SAMPLE_CUSTOM_TOKENS = String.raw`registerCustomToken('foo', (ctx) => {
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  return ctx.noteFileName + ctx.app.appId + formatValue + ctx.obsidian.apiVersion;
});

registerCustomToken('bar', async (ctx) => {
  await sleep(100);
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  const filledTemplate = await ctx.fillTemplate('qux \${quux} corge \${grault:{garply:\'waldo\'}} fred');
  return ctx.noteFileName + ctx.app.appId + formatValue + ctx.obsidian.apiVersion + filledTemplate;
});`;

export enum AttachmentRenameMode {
  None = 'None',

  OnlyPastedImages = 'Only pasted images',
  // eslint-disable-next-line perfectionist/sort-enums -- Need to keep enum order.
  All = 'All'
}

export enum CollectAttachmentUsedByMultipleNotesMode {
  Cancel = 'Cancel',
  Copy = 'Copy',
  Move = 'Move',
  Prompt = 'Prompt',
  Skip = 'Skip'
}

export enum ConvertImagesToJpegMode {
  AllImages = 'All images',
  AllImagesExceptAlreadyJpegFiles = 'All images except already JPEG files',
  None = 'None',
  OnlyPastedClipboardPngImages = 'Only pasted clipboard PNG images'
}

export enum DefaultImageSizeDimension {
  Height = 'height',
  Width = 'width'
}

export enum MoveAttachmentToProperFolderUsedByMultipleNotesMode {
  Cancel = 'Cancel',
  CopyAll = 'CopyAll',
  Prompt = 'Prompt',
  Skip = 'Skip'
}

export class PluginSettings {
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  public attachmentFolderPath = './assets/${noteFileName}';
  public attachmentRenameMode: AttachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
  public collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;
  public collectedAttachmentFileName = '';
  public convertImagesToJpegMode: ConvertImagesToJpegMode = ConvertImagesToJpegMode.None;
  public defaultImageSize = '';
  public defaultImageSizeDimension: DefaultImageSizeDimension = DefaultImageSizeDimension.Width;
  public downloadNetworkImages = false;
  public duplicateNameSeparator = ' ';
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  public generatedAttachmentFileName = 'file-${date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}';

  /**
   * Whether the user has dismissed the suggestion to install Advanced Rename and Delete Handler.
   *
   * A decline has to outlive a reload, so it is persisted rather than held in memory.
   */
  public isAdvancedRenameAndDeleteHandlerSuggestionDeclined = false;

  // eslint-disable-next-line no-magic-numbers -- Magic numbers are OK in settings.
  public jpegQuality = 0.8;
  public markdownUrlFormat = '';
  public moveAttachmentToProperFolderUsedByMultipleNotesMode: MoveAttachmentToProperFolderUsedByMultipleNotesMode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
  // eslint-disable-next-line no-magic-numbers -- Magic numbers are OK in settings.
  public networkImageDownloadTimeoutInSeconds = 30;

  /**
   * The rename/delete values this plugin held before 12.0.0, waiting to be offered to Advanced Rename and
   * Delete Handler.
   *
   * Non-`null` means an offer is still pending; `null` means there is nothing to offer, which is also what a
   * fresh install has. ONE nullable object rather than a flag plus values, so a fresh install can never be
   * told it has a migration waiting, and so a user who has not installed the other plugin yet does not lose
   * what they configured.
   */
  public proposedRenameDeleteSettings: MigratableSettings | null = null;

  public renamedAttachmentFileName = '';
  public shouldPreserveImageMetadata = false;
  public shouldRenameAttachmentsCreatedByOtherPlugins = false;
  public shouldRenameCollectedAttachments = false;
  public shouldSetLinkDisplayTextToAttachmentFileName = false;
  public shouldSkipCollectingAttachmentsReferencedByRawPath = false;
  public specialCharacters = String.raw`#^[]|*\<>:?/`;
  public specialCharactersReplacement = '-';
  // eslint-disable-next-line no-magic-numbers -- Magic numbers are OK in settings.
  public timeoutInSeconds = 5;
  public version = '';
  /**
   * Folders whose whole hierarchy travels as one attachment.
   *
   * Same vocabulary as the include / exclude path settings: a plain entry is a path from the vault
   * root, and an entry wrapped in `/` is a regular expression. Matching a folder *name* wherever it
   * appears therefore needs the regular-expression form, e.g. `/(^|\/)[^/]+_files(\/|$)/`.
   */
  public get attachmentUnitFolderPaths(): string[] {
    return this._attachmentUnitFolderPaths.excludePaths;
  }

  public set attachmentUnitFolderPaths(value: string[]) {
    this._attachmentUnitFolderPaths.excludePaths = value;
  }

  // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
  public get customTokensStr(): string {
    return this._customTokensStr;
  }

  // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
  public set customTokensStr(value: string) {
    // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
    this._customTokensStr = value;
  }

  public get excludePathsFromAttachmentCollecting(): string[] {
    return this._attachmentCollectingPaths.excludePaths;
  }

  public set excludePathsFromAttachmentCollecting(value: string[]) {
    this._attachmentCollectingPaths.excludePaths = value;
  }

  public get excludePathsFromMultipleNotesCheck(): string[] {
    return this._multipleNotesCheckPaths.excludePaths;
  }

  public set excludePathsFromMultipleNotesCheck(value: string[]) {
    this._multipleNotesCheckPaths.excludePaths = value;
  }

  public get specialCharactersRegExp(): RegExp {
    return new RegExp(`[${escapeRegExp(this.specialCharacters)}]+`, 'gu');
  }

  private readonly _attachmentCollectingPaths = new PathSettings();
  // Only the exclude half is exposed: `isPathIgnored` then reduces to "matches one of these
  // Patterns", which is what a designation list needs. Same shape as `_attachmentCollectingPaths`.
  private readonly _attachmentUnitFolderPaths = new PathSettings();
  // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
  private _customTokensStr = '';
  private readonly _multipleNotesCheckPaths = new PathSettings();

  public getNetworkImageDownloadTimeoutInMilliseconds(): number {
    const MILLISECONDS_IN_SECOND = 1000;
    return this.networkImageDownloadTimeoutInSeconds * MILLISECONDS_IN_SECOND;
  }

  public getTimeoutInMilliseconds(): number {
    const MILLISECONDS_IN_SECOND = 1000;
    return this.timeoutInSeconds === 0 ? INFINITE_TIMEOUT : this.timeoutInSeconds * MILLISECONDS_IN_SECOND;
  }

  public isAttachmentUnitFolder(path: string): boolean {
    return this._attachmentUnitFolderPaths.isPathIgnored(path);
  }

  public isExcludedFromAttachmentCollecting(path: string): boolean {
    return this._attachmentCollectingPaths.isPathIgnored(path);
  }

  public isExcludedFromMultipleNotesCheck(path: string): boolean {
    return this._multipleNotesCheckPaths.isPathIgnored(path);
  }
}
