import { INFINITE_TIMEOUT } from 'obsidian-dev-utils/abort-controller';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import { PathSettings } from 'obsidian-dev-utils/obsidian/path-settings';
import { escapeRegExp } from 'obsidian-dev-utils/reg-exp';

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
  public emptyFolderBehavior: EmptyFolderBehavior = EmptyFolderBehavior.DeleteWithEmptyParents;
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  public generatedAttachmentFileName = 'file-${date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}';
  // eslint-disable-next-line no-magic-numbers -- Magic numbers are OK in settings.
  public jpegQuality = 0.8;
  public markdownUrlFormat = '';
  public moveAttachmentToProperFolderUsedByMultipleNotesMode: MoveAttachmentToProperFolderUsedByMultipleNotesMode = MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;
  // eslint-disable-next-line no-magic-numbers -- Magic numbers are OK in settings.
  public networkImageDownloadTimeoutInSeconds = 30;

  /**
   * Which referencing note owns an attachment that several notes reference, highest priority first.
   *
   * Empty by default, which keeps today's behavior: the ambiguity falls to
   * `collectAttachmentUsedByMultipleNotesMode`. A tie between equally-ranked notes falls there too,
   * deliberately — see `note-priority.ts`.
   */
  public notePriorities: readonly string[] = [];

  public renamedAttachmentFileName = '';
  public shouldDeleteOrphanAttachments = false;
  public shouldHandleRenames = true;
  public shouldPreserveImageMetadata = false;
  public shouldRenameAttachmentFiles = false;
  public shouldRenameAttachmentFolder = true;
  public shouldRenameCollectedAttachments = false;

  /**
   * Whether to move an attachment that a deletion would otherwise strand.
   *
   * When a note (or its attachment folder) is deleted while another note still references one of its
   * attachments, the attachment survives but is left sitting in a folder whose owning note is gone.
   * With this on, it is moved into the surviving note's attachment folder instead, keeping its file
   * name.
   *
   * Takes effect only while `shouldDeleteOrphanAttachments` is on — that is the setting which hands
   * the delete path to the rename/delete handler in the first place.
   */
  public shouldRescueSharedAttachments = false;

  public shouldSetLinkDisplayTextToAttachmentFileName = false;
  public shouldSkipCollectingAttachmentsReferencedByRawPath = false;
  public specialCharacters = String.raw`#^[]|*\<>:?/`;
  public specialCharactersReplacement = '-';
  // eslint-disable-next-line no-magic-numbers -- Magic numbers are OK in settings.
  public timeoutInSeconds = 5;
  public treatAsAttachmentExtensions: readonly string[] = ['.excalidraw.md'];
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

  public get excludePaths(): string[] {
    return this._pathSettings.excludePaths;
  }

  public set excludePaths(value: string[]) {
    this._pathSettings.excludePaths = value;
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

  public get includePaths(): string[] {
    return this._pathSettings.includePaths;
  }

  public set includePaths(value: string[]) {
    this._pathSettings.includePaths = value;
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
  private readonly _pathSettings = new PathSettings();

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

  public isPathIgnored(path: string): boolean {
    return this._pathSettings.isPathIgnored(path);
  }
}
