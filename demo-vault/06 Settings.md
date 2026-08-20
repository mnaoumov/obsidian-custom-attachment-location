# Settings

Open **Settings -> Community plugins -> Custom Attachment Location** to configure the plugin. Each option below lists the setting key stored in the plugin's `data.json`. Many of these accept **patterns with tokens** - see [03 Tokens and patterns](<./03 Tokens and patterns.md>).

## Location for new attachments

- `attachmentFolderPath`
  - the folder each new attachment is saved into (a pattern). Start it with `./` for a path relative to the note; otherwise it is relative to the vault root.
- `includePaths`
  - if non-empty, the plugin only applies within these paths.
- `excludePaths`
  - paths where the plugin does nothing (Obsidian's default behavior is used instead).

## Attachment file naming

- `generatedAttachmentFileName`
  - the name pattern for a newly created attachment.
- `renamedAttachmentFileName`
  - the name pattern used when an attachment is renamed alongside its note.
- `shouldRenameAttachmentFiles`
  - rename attachment files when the note is renamed.
- `shouldRenameAttachmentFolder`
  - rename the per-note attachment folder when the note is renamed.
- `attachmentRenameMode`
  - which attachments get renamed on paste: none, only pasted images, or all.
- `duplicateNameSeparator`
  - the separator inserted before the counter when a name already exists (e.g. `file 1.png`).
- `specialCharacters`
  - characters stripped/replaced from generated folder and file names.
- `specialCharactersReplacement`
  - the string that replaces those special characters.

## Markdown URL

- `markdownUrlFormat`
  - a pattern for the link text inserted into the note. Leave blank for the default; setting it forces Markdown links even when Obsidian is configured for wikilinks.

## Link display text

- `shouldSetLinkDisplayTextToAttachmentFileName`
  - when inserting a link to an **attachment**, use the attachment's base name (without extension) as the link's display text. Notes are left alone, and an explicit alias or a cached image size still wins. See [07 Link display text](<./07 Link display text.md>).

## Custom tokens

- `customTokensStr`
  - JavaScript that registers your own tokens (see [04 Custom tokens](<./04 Custom tokens.md>)).

## Collecting attachments

- `shouldRenameCollectedAttachments`
  - rename attachments processed by the **Collect attachments** commands.
- `collectedAttachmentFileName`
  - the name pattern used for collected attachments.
- `collectAttachmentUsedByMultipleNotesMode`
  - what to do when a collected attachment is referenced by several notes: cancel, copy, move, prompt, or skip.
- `moveAttachmentToProperFolderUsedByMultipleNotesMode`
  - the same choice for the **Move attachment to proper folder** command.
- `attachmentUnitFolderPaths`
  - folders whose whole hierarchy is one attachment, so collecting moves the entire folder rather than the single linked file. Use it for a saved page next to its `_files/` folder or a drawing next to the images it references. See [05 Collect attachments](<./05 Collect attachments.md>).
- `excludePathsFromAttachmentCollecting`
  - paths ignored by the collecting commands.
- `excludePathsFromMultipleNotesCheck`
  - notes on these paths are ignored when deciding whether a collected attachment is used by multiple notes, so a shared embed (e.g. an `.excalidraw` drawing) does not block collecting.
- `shouldSkipCollectingAttachmentsReferencedByRawPath`
  - a safety net for attachments referenced by other plugins' non-standard syntaxes. When on, before collecting an attachment the plugin also scans every note's raw text for the attachment's path or file name; if a note references it in a format Obsidian does not index, the attachment is treated as still used and left in place (it is not moved or renamed). Default off. See [05 Collect attachments](<./05 Collect attachments.md>).

## Renames and deletions

- `shouldHandleRenames`
  - keep links and attachment folders consistent when notes are renamed or moved.
- `shouldDeleteOrphanAttachments`
  - delete an attachment when the note that owned it is deleted.
- `emptyFolderBehavior`
  - whether to keep or delete attachment folders that become empty.
- `treatAsAttachmentExtensions`
  - extra file extensions (like `.excalidraw.md`) treated as attachments.

## Image conversion and size

- `convertImagesToJpegMode`
  - convert pasted/dragged images to JPEG (none, only clipboard PNGs, all, or all except existing JPEGs).
- `jpegQuality`
  - the JPEG quality (0-1) used for conversion.
- `defaultImageSize`
  - a default size applied to inserted images (blank leaves them untouched).
- `defaultImageSizeDimension`
  - whether `defaultImageSize` sets the width or the height.

## Network images

- `downloadNetworkImages`
  - download remote images referenced in a note into the vault.
- `networkImageDownloadTimeoutInSeconds`
  - how long to wait for each network image download.

## Timing and bookkeeping

- `timeoutInSeconds`
  - timeout for the plugin's longer operations (0 means wait indefinitely).
- `version`
  - the settings schema version; managed by the plugin, not edited by hand.
