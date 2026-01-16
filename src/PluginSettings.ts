import { INFINITE_TIMEOUT } from 'obsidian-dev-utils/AbortController';
import { PathSettings } from 'obsidian-dev-utils/obsidian/Plugin/PathSettings';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/RenameDeleteHandler';
import { escapeRegExp } from 'obsidian-dev-utils/RegExp';

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
  public duplicateNameSeparator = ' ';
  public emptyFolderBehavior: EmptyFolderBehavior = EmptyFolderBehavior.DeleteWithEmptyParents;
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  public generatedAttachmentFileName = 'file-${date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}';
  // eslint-disable-next-line no-magic-numbers -- Magic numbers are OK in settings.
  public jpegQuality = 0.8;
  public markdownUrlFormat = '';
  public moveAttachmentToProperFolderUsedByMultipleNotesMode: MoveAttachmentToProperFolderUsedByMultipleNotesMode =
    MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll;

  public renamedAttachmentFileName = '';
  public shouldDeleteOrphanAttachments = false;
  public shouldHandleRenames = true;
  public shouldRenameAttachmentFiles = false;
  public shouldRenameAttachmentFolder = true;
  public shouldRenameCollectedAttachments = false;
  public specialCharacters = '#^[]|*\\<>:?/';
  public specialCharactersReplacement = '-';
  // eslint-disable-next-line no-magic-numbers -- Magic numbers are OK in settings.
  public timeoutInSeconds = 5;
  public treatAsAttachmentExtensions: readonly string[] = ['.excalidraw.md'];
  public version = '';
  public get customTokensStr(): string {
    return this._customTokensStr;
  }

  public set customTokensStr(value: string) {
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
  private _customTokensStr = '';
  private readonly _pathSettings = new PathSettings();

  public getTimeoutInMilliseconds(): number {
    const MILLISECONDS_PER_SECOND = 1000;
    return this.timeoutInSeconds === 0 ? INFINITE_TIMEOUT : this.timeoutInSeconds * MILLISECONDS_PER_SECOND;
  }

  public isExcludedFromAttachmentCollecting(path: string): boolean {
    return this._attachmentCollectingPaths.isPathIgnored(path);
  }

  public isPathIgnored(path: string): boolean {
    return this._pathSettings.isPathIgnored(path);
  }
}
