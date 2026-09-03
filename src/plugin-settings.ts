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

/**
 * Which attachments the vault sweep judges WITHOUT going through an owning note.
 *
 * The note-driven sweep reaches an attachment folder only through the note that owns it, so a folder whose
 * note is gone — removed by a sync client rather than by Obsidian, say — is never visited and its files sit
 * there forever. This mode adds a second, attachment-driven pass for exactly that case.
 *
 * The scope has to be NAMED rather than derived. `attachmentFolderPath` is a per-note template and cannot be
 * run backwards — `${prompt}` and `${random}` throw away the very value the folder name was built from, and
 * two notes can resolve to one folder — so there is no vault-wide attachment root to enumerate. See the file
 * comment of `note-owner-resolver.ts`, which settles the same point for the other direction.
 *
 * {@link None} is the default, because the two list modes delete files no note points at, which is a file
 * the user may be keeping deliberately.
 */
export enum OrphanAttachmentScanMode {
  EntireVault = 'Entire vault',
  ListedPaths = 'Listed paths',
  None = 'None'
}

/**
 * Which of the attachments OTHER plugins create get this plugin's folder and file-name templates applied.
 *
 * The two list modes are the two polarities issue #77 asks for: name the plugins it applies to, or name the
 * plugins it skips. They both need the creating plugin to be identified, which is best-effort — the id is
 * read off the call stack at the write, and no id is recovered for a file Obsidian core, a sync client or
 * raw `fs` wrote. An attachment whose creator cannot be identified is simply not a member of the list, so
 * {@link OnlyListedPlugins} leaves it alone and {@link AllExceptListedPlugins} renames it.
 */
export enum RenameAttachmentsCreatedByOtherPluginsMode {
  All = 'All',
  AllExceptListedPlugins = 'All except listed plugins',
  None = 'None',
  OnlyListedPlugins = 'Only listed plugins'
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
  public orphanAttachmentScanMode: OrphanAttachmentScanMode = OrphanAttachmentScanMode.None;

  /**
   * The plugin ids the two list modes of {@link renameAttachmentsCreatedByOtherPluginsMode} are scoped to.
   *
   * Ids, not paths — a plain array rather than the {@link PathSettings} pair the path lists use, since
   * there is nothing here to match by prefix or regular expression. `readonly` so it binds straight to the
   * multi-select, whose value is a `readonly string[]`, with no converter pair in between.
   */
  public otherPluginIdsForAttachmentRename: readonly string[] = [];

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

  public renameAttachmentsCreatedByOtherPluginsMode: RenameAttachmentsCreatedByOtherPluginsMode = RenameAttachmentsCreatedByOtherPluginsMode.None;
  public renamedAttachmentFileName = '';
  public shouldPreserveImageMetadata = false;
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

  /**
   * The folders {@link OrphanAttachmentScanMode.ListedPaths} confines the attachment-driven pass to.
   *
   * Same vocabulary as {@link attachmentUnitFolderPaths}: a plain entry is a path from the vault root, and
   * an entry wrapped in `/` is a regular expression, which is what matching a folder *name* wherever it
   * appears needs — e.g. `/\/!!files\//`.
   */
  public get orphanAttachmentScanPaths(): string[] {
    return this._orphanAttachmentScanPaths.excludePaths;
  }

  public set orphanAttachmentScanPaths(value: string[]) {
    this._orphanAttachmentScanPaths.excludePaths = value;
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
  // Exclude half only, same as `_attachmentUnitFolderPaths` — a scope list, not an include/exclude pair.
  private readonly _orphanAttachmentScanPaths = new PathSettings();

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

  /**
   * Whether an attachment is in scope for the attachment-driven pass, which needs no owning note.
   *
   * The mode's whole meaning lives here rather than being spread through the sweep, so there is one place
   * that says what each mode admits.
   *
   * @param path - The vault-relative path of the attachment.
   * @returns `true` when the pass may judge it.
   */
  public isOrphanAttachmentScanCandidate(path: string): boolean {
    const mode = this.orphanAttachmentScanMode;
    if (mode === OrphanAttachmentScanMode.None) {
      return false;
    }

    /*
     * Ifs rather than an exhaustive `switch`: `default-case` demands a branch no enum value can reach, and
     * an unreachable branch is exactly what the coverage bar forbids.
     */
    if (mode === OrphanAttachmentScanMode.EntireVault) {
      return true;
    }

    return this._orphanAttachmentScanPaths.isPathIgnored(path);
  }

  /**
   * Whether the creating plugin has to be identified before an externally created attachment can be judged.
   *
   * `false` for both non-list modes, which is what keeps the stack capture off the hot path entirely for a
   * user who never opts into a list.
   *
   * @returns `true` when the current mode consults the plugin id.
   */
  public needsCreatingPluginAttribution(): boolean {
    return this.renameAttachmentsCreatedByOtherPluginsMode === RenameAttachmentsCreatedByOtherPluginsMode.OnlyListedPlugins
      || this.renameAttachmentsCreatedByOtherPluginsMode === RenameAttachmentsCreatedByOtherPluginsMode.AllExceptListedPlugins;
  }

  /**
   * Whether the path list scoping the attachment-driven pass is in play.
   *
   * Phrased as a question about the domain rather than as an enum comparison, so the settings tab's
   * visibility predicate reads as what it means. Mirrors {@link needsCreatingPluginAttribution}.
   *
   * @returns `true` when the current mode consults {@link orphanAttachmentScanPaths}.
   */
  public needsOrphanAttachmentScanPaths(): boolean {
    return this.orphanAttachmentScanMode === OrphanAttachmentScanMode.ListedPaths;
  }

  /**
   * Decides whether an attachment a foreign plugin created gets this plugin's templates applied.
   *
   * `null` — the creator could not be identified — is deliberately treated as "not one of the listed
   * plugins" rather than as its own case: it is skipped under {@link RenameAttachmentsCreatedByOtherPluginsMode.OnlyListedPlugins}
   * and renamed under {@link RenameAttachmentsCreatedByOtherPluginsMode.AllExceptListedPlugins}, which is the
   * literal reading of both modes.
   *
   * @param pluginId - The `manifest.id` of the plugin that created the attachment, or `null` when it could
   * not be identified.
   * @returns `true` when the attachment should be renamed.
   */
  public shouldRenameAttachmentCreatedByPlugin(pluginId: null | string): boolean {
    const mode = this.renameAttachmentsCreatedByOtherPluginsMode;
    if (mode === RenameAttachmentsCreatedByOtherPluginsMode.None) {
      return false;
    }

    if (mode === RenameAttachmentsCreatedByOtherPluginsMode.All) {
      return true;
    }

    /*
     * Ifs rather than an exhaustive `switch`: `default-case` demands a branch no enum value can reach, and
     * an unreachable branch is exactly what the coverage bar forbids.
     */
    const isListed = pluginId !== null && this.otherPluginIdsForAttachmentRename.includes(pluginId);
    return mode === RenameAttachmentsCreatedByOtherPluginsMode.OnlyListedPlugins ? isListed : !isListed;
  }
}
