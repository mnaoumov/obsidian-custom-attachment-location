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
  const filledTemplate = await ctx.fillTemplate('qux {{quux}} corge {{grault:{garply:\'waldo\'}}} fred');
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
 * run backwards — `{{prompt}}` and `{{random}}` throw away the very value the folder name was built from, and
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
  public attachmentFolderPath = './assets/{{noteFileName}}';
  public attachmentRenameMode: AttachmentRenameMode = AttachmentRenameMode.OnlyPastedImages;
  public collectAttachmentUsedByMultipleNotesMode: CollectAttachmentUsedByMultipleNotesMode = CollectAttachmentUsedByMultipleNotesMode.Skip;
  public collectedAttachmentFileName = '';

  /**
   * Where the `Collect attachments` commands put an attachment, when that is not where a NEW attachment goes.
   *
   * The folder twin of {@link collectedAttachmentFileName}, and empty means the same thing there as here:
   * fall back to the setting that governs new attachments, so a user who never opens this sees the behavior
   * they always had. The two destinations are decoupled for the export workflow issue #78 describes — a
   * shared `_Attachments` folder while a note is being worked on, and a portable `./{{noteFileName}}.assets`
   * beside the note once it is collected for export — which until now needed the one setting flipped before
   * each export and flipped back afterwards.
   *
   * Only the collecting commands read it. `Move attachment to proper folder` deliberately keeps
   * {@link attachmentFolderPath}: it answers where an attachment BELONGS, which is the new-attachment
   * location by definition.
   */
  public collectedAttachmentFolderPath = '';

  public convertImagesToJpegMode: ConvertImagesToJpegMode = ConvertImagesToJpegMode.None;
  public defaultImageSize = '';
  public defaultImageSizeDimension: DefaultImageSizeDimension = DefaultImageSizeDimension.Width;
  public downloadNetworkImages = false;
  public duplicateNameSeparator = ' ';

  /**
   * Attachment file types that are SHARED on purpose, so the multiple-notes check never runs for them.
   *
   * The file-type twin of {@link excludePathsFromMultipleNotesCheck}, which answers the other axis: that one names
   * the NOTES that do not count as a second referrer, this one names the ATTACHMENTS that are expected to have
   * several (issue #80 — the reporter's `.af` files, which every note in a project points at by design). Without it
   * the only way to stop the prompt is to list every note, which is the whole vault.
   *
   * A plain array rather than the {@link PathSettings} pair the path lists use: an extension has nothing to
   * prefix-match and no include half, the same reasoning as {@link otherPluginIdsForAttachmentRename}. Matching is
   * done by {@link isExtensionExcludedFromMultipleNotesCheck}, which spells out the normalization.
   *
   * Read by the two commands that RELOCATE — `Collect attachments` and `Move attachment to proper folder` — and
   * deliberately NOT by `Delete unused attachments`. There the same question is asked in the opposite polarity: the
   * remover uses the multiple-notes exclusion to DROP notes from an attachment's backlink set, and an attachment
   * with nothing left in that set is trashed. Honoring an extension list there would delete exactly the shared files
   * this setting exists to leave alone, so the asymmetry is deliberate rather than an oversight.
   */
  public excludeExtensionsFromMultipleNotesCheck: string[] = [];

  public generatedAttachmentFileName = 'file-{{date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}}';

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

  /**
   * Whether a note's attachments are collected each time the note changes, as if
   * `Collect attachments in current note` had been run on it.
   *
   * Off by default. Collecting moves files, and with this on it happens on every save of a note, without being
   * asked. It is the setting Consistent Attachments and Links offered before it handed collecting over to this
   * plugin, and it is migrated from there.
   */
  public shouldCollectAttachmentsAutomatically = false;

  /**
   * Whether a new attachment goes wherever Obsidian's own *Default location for new attachments* says.
   *
   * On, {@link attachmentFolderPath} is not consulted at all: the folder is Obsidian's setting, resolved the
   * way Obsidian resolves it, and Obsidian's setting page stays the one place that decides. It is kept rather
   * than cleared, so turning the mode off again restores the template the user had.
   *
   * A flag rather than a sentinel value inside the template, so a template can never be mistaken for the mode
   * and the mode can never destroy the template. Only the FOLDER follows Obsidian; the file-name settings
   * still apply. An explicit {@link collectedAttachmentFolderPath} still wins for the collecting commands, as
   * it does over the template.
   *
   * On by default since 13.0.0, so a fresh install changes nothing about where attachments land until the user
   * picks a pattern. The template default stays `./assets/{{noteFileName}}`, the default of every earlier
   * release, so a user whose attachments moved on the upgrade switches this off and has the old behavior back.
   */
  public shouldFollowObsidianAttachmentLocation = true;

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
  // patterns", which is what a designation list needs. Same shape as `_attachmentCollectingPaths`.
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
   * Whether an attachment's file type is one of the deliberately shared ones.
   *
   * The whole matching rule of {@link excludeExtensionsFromMultipleNotesCheck} lives here, so there is one place
   * that says what an entry means:
   *
   * - **One optional leading dot.** `af` and `.af` are the same entry, because a user types what they see in the
   *   file name and both spellings are what they see.
   * - **Case-insensitive on both sides.** A vault that has passed through Windows, macOS and a sync client holds
   *   `.af`, `.AF` and `.Af` for one file type.
   * - **A literal suffix test, not a glob.** `foo.af` matches the entry `af` because it ends with `.af`. That is a
   *   superset of comparing only the last dotted segment, which is what lets a compound suffix be named outright —
   *   `excalidraw.md` matches `Drawing.excalidraw.md` and nothing else. No regular-expression form: the path
   *   setting beside it already carries `/…/` for anything more elaborate, and a closed one-word value does not
   *   need a second vocabulary.
   *
   * An entry that is blank, or is nothing but dots, matches nothing — otherwise an accidental empty line in the
   * text area would turn the check off for the entire vault.
   *
   * @param path - The vault-relative path of the attachment.
   * @returns `true` when the multiple-notes check should be skipped for it.
   */
  public isExtensionExcludedFromMultipleNotesCheck(path: string): boolean {
    const lowerCasePath = path.toLowerCase();
    return this.excludeExtensionsFromMultipleNotesCheck.some((extension) => {
      const normalizedExtension = extension.trim().replace(/^\./, '').toLowerCase();
      return normalizedExtension !== '' && !/^\.*$/.test(normalizedExtension) && lowerCasePath.endsWith(`.${normalizedExtension}`);
    });
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

    /*
     * Comparisons rather than an exhaustive `switch`: `default-case` demands a branch no enum value can reach,
     * and an unreachable branch is exactly what the coverage bar forbids.
     */
    return mode !== OrphanAttachmentScanMode.None
      && (mode === OrphanAttachmentScanMode.EntireVault || this._orphanAttachmentScanPaths.isPathIgnored(path));
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
