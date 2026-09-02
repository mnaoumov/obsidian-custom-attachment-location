# Settings

Open **Settings -> Community plugins -> Custom Attachment Location** to configure the plugin. Each option below lists the setting key stored in the plugin's `data.json`. Many of these accept **patterns with tokens** - see [03 Tokens and patterns](<./03 Tokens and patterns.md>).

## Location for new attachments

- `attachmentFolderPath`
  - the folder each new attachment is saved into (a pattern). Start it with `./` for a path relative to the note; otherwise it is relative to the vault root.

## Attachment file naming

- `generatedAttachmentFileName`
  - the name pattern for a newly created attachment.
- `renamedAttachmentFileName`
  - the name pattern used when an attachment is renamed alongside its note.
- `attachmentRenameMode`
  - which attachments get renamed on paste: none, only pasted images, or all.
- `shouldRenameAttachmentsCreatedByOtherPlugins`
  - **off by default.** Apply the attachment folder and file name settings to attachments **other plugins** create. Some plugins write an attachment into the vault under a name of their own rather than asking Obsidian where it belongs — Media Extended's video screenshots, for instance — which puts them out of this plugin's reach until the file already exists. `attachmentRenameMode` cannot help there, not even on `All`: that setting only governs attachments that go through Obsidian's own save. With this on, such a file is moved and renamed just after it appears, and the link the creating plugin inserted is repointed at it — including when that link is still sitting unsaved in the editor, which is the usual case. Only files created while a note is open, and created within the last few seconds, are touched — never files arriving from a sync or a vault import. The note does not have to be the focused one: Media Extended's screenshot command runs in its own player pane, so the active file at that moment is the video, and the most recently used note is used instead.
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

## Renames and deletions — moved to another plugin in 12.0.0

Renames and deletions are handled by **[Advanced Rename and Delete Handler](https://obsidian.md/plugins?id=advanced-rename-and-delete-handler)**, not by this plugin. Two plugins handling one rename corrupt links and move attachments twice, so exactly one plugin owns it, and these settings live there:

- `shouldHandleRenames`, `shouldHandleDeletions` (spelled `shouldDeleteOrphanAttachments` here before 12.0.0), `shouldRenameAttachmentFiles`, `shouldRenameAttachmentFolder`, `shouldRescueSharedAttachments`, `emptyFolderBehavior`, `treatAsAttachmentExtensions`, `notePriorities`, `includePaths` and `excludePaths`.

Upgrading offers to move whatever you had set into that plugin, once. Until you accept, your values are kept in `proposedRenameDeleteSettings` below and the offer returns; cancelling does not throw them away.

Five of those settings still matter to **this** plugin's own commands — Collect attachments, Delete unused attachments and Go to owning note all need to know what an attachment is, which paths to skip, which note owns a shared attachment and what to do with an emptied folder. This plugin reads them back from Advanced Rename and Delete Handler rather than keeping a second copy, so there is one place to set them.

Two things follow, and are worth knowing before you decline the suggestion:

- **`includePaths` / `excludePaths` now scope both plugins.** Excluding a folder from rename handling also excludes it from this plugin's Collect attachments and Delete unused attachments.
- **Without Advanced Rename and Delete Handler installed, these fall back to this plugin's own defaults** — an empty path list, an empty priority list, `.excalidraw.md` as the one attachment extension, and `DeleteWithEmptyParents` for emptied folders. Nothing is lost: your values stay in `proposedRenameDeleteSettings` and are offered again the moment that plugin appears. The same fallback applies when it is installed but older than 1.2.0, which is the version that first offers these values back — the migration is still offered, so you can hand your settings over and then update.

## Image conversion and size

- `convertImagesToJpegMode`
  - convert pasted/dragged images to JPEG (none, only clipboard PNGs, all, or all except existing JPEGs).
- `jpegQuality`
  - the JPEG quality (0-1) used for conversion.
- `shouldPreserveImageMetadata`
  - carry the original's EXIF, GPS, XMP and ICC profile data into the converted JPEG, so photos keep the geolocation that mapping plugins read. Only works when the original is already a JPEG, since nothing else stores that data in a copyable form, and the orientation is always reset because the conversion has already rotated the pixels. Default off: the same data also carries camera serial numbers and the times and places the photos were taken, which matters if you share your vault.
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
- `isAdvancedRenameAndDeleteHandlerSuggestionDeclined`
  - whether you dismissed the banner suggesting Advanced Rename and Delete Handler. Persisted so a decline survives a reload; managed by the plugin, not edited by hand.
- `proposedRenameDeleteSettings`
  - the rename/delete values this plugin held before 12.0.0, waiting to be offered to Advanced Rename and Delete Handler. `null` once the migration is applied, and `null` on a fresh install, which is how the plugin knows never to offer a migration of values you never set. Managed by the plugin, not edited by hand.
