# Settings

Open **Settings -> Community plugins -> Custom Attachment Location** to configure the plugin. Each option below lists the setting key stored in the plugin's `data.json`. Many of these accept **patterns with tokens** - see [03 Tokens and patterns](<./03 Tokens and patterns.md>).

## Location for new attachments

- `shouldFollowObsidianAttachmentLocation`
  - **On by default since 13.0.0.** New attachments go wherever Obsidian's own **Files and links -> Default location for new attachments** says, and `attachmentFolderPath` is not used. So a fresh install changes nothing until you turn it off and pick a pattern. This vault has it off, so the pattern demos work. See [01 Attachment folder location](<./01 Attachment folder location.md>).
- `attachmentFolderPath`
  - the folder each new attachment is saved into (a pattern), while `shouldFollowObsidianAttachmentLocation` is off. Start it with `./` for a path relative to the note; otherwise it is relative to the vault root. Defaults to `./assets/{{noteFileName}}`, the location every release before 13.0.0 used out of the box.

## Attachment file naming

- `generatedAttachmentFileName`
  - the name pattern for a newly created attachment.
- `renamedAttachmentFileName`
  - the name pattern used when an attachment is renamed alongside its note.
- `attachmentRenameMode`
  - which attachments get renamed on paste: none, only pasted images, or all.
- `renameAttachmentsCreatedByOtherPluginsMode`
  - **`None` by default.** Apply the attachment folder and file name settings to attachments **other plugins** create. Some plugins write an attachment into the vault under a name of their own rather than asking Obsidian where it belongs — Media Extended's video screenshots, for instance — which puts them out of this plugin's reach until the file already exists. `attachmentRenameMode` cannot help there, not even on `All`: that setting only governs attachments that go through Obsidian's own save. Once this is not `None`, such a file is moved and renamed just after it appears, and the link the creating plugin inserted is repointed at it — including when that link is still sitting unsaved in the editor, which is the usual case. Only files created while a note is open, and created within the last few seconds, are touched — never files arriving from a sync or a vault import. The note does not have to be the focused one: Media Extended's screenshot command runs in its own player pane, so the active file at that moment is the video, and the most recently used note is used instead. The four values are `None` (leave them alone), `All` (every plugin), `Only listed plugins` and `All except listed plugins` — the last two scoped by `otherPluginIdsForAttachmentRename`.
- `otherPluginIdsForAttachmentRename`
  - the plugins the two list modes of `renameAttachmentsCreatedByOtherPluginsMode` are scoped to, picked by name from the plugins you have installed. Empty by default, and ignored entirely under `None` and `All`. A plugin you disable or uninstall keeps its place in the list, shown by its id, so re-enabling it needs no change here.
  - **Which plugin created a file is worked out from the call stack of the write, and that is best-effort.** Obsidian runs each community plugin's code under a marker naming it, so a write made from that code can be traced back. Nothing names Obsidian's own writes, a sync client's, or a plugin that defers its write past the moment it was asked for — such a file counts as *not* being in the list, so `Only listed plugins` leaves it alone and `All except listed plugins` renames it. If a plugin you listed is not being caught, `All` still works as it always did.
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

- `shouldCollectAttachmentsAutomatically`
  - collect a note's attachments each time the note changes, without asking. Default off. See [05 Collect attachments](<./05 Collect attachments.md>).
- `shouldRenameCollectedAttachments`
  - rename attachments processed by the **Collect attachments** commands.
- `collectedAttachmentFileName`
  - the name pattern used for collected attachments.
- `collectedAttachmentFolderPath`
  - the folder the **Collect attachments** commands put an attachment into (a pattern), when that is not where *new* attachments go. Empty by default, which means collecting uses `attachmentFolderPath` exactly as it always has. Set it to decouple the two destinations - a shared `_Attachments` folder while you are working on a note, and `./{{noteFileName}}.assets` beside the note once you collect it for export. Only the collecting commands read it; **Move attachment to proper folder** keeps using `attachmentFolderPath`, because it answers where an attachment *belongs*, which is the new-attachment location. See [05 Collect attachments](<./05 Collect attachments.md>).
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
- `excludeExtensionsFromMultipleNotesCheck`
  - the same question from the other side: attachments with these file extensions skip the multiple-notes check entirely, however many notes reference them. Use it for file types that are shared between notes on purpose. Write one extension per line, with or without the leading dot; matching ignores case, and a compound extension such as `excalidraw.md` works. It is read by **Collect attachments** and **Move attachment to proper folder**, and deliberately not by **Delete unused attachments** - see [08 Delete unused attachments](<./08 Delete unused attachments.md>).
- `orphanAttachmentScanMode`
  - whether **Delete unused attachments in entire vault** also looks for attachments no note owns at all — the case where a note was deleted and its attachment folder was left behind, which nothing leads to any more. `None` (default), `Listed paths`, or `Entire vault`. Applies to the whole-vault command only. See [08 Delete unused attachments](<./08 Delete unused attachments.md>).
- `orphanAttachmentScanPaths`
  - the folders `Listed paths` looks in. Same vocabulary as `attachmentUnitFolderPaths`: a plain entry is matched from the vault root, and an entry wrapped in `/` is a regular expression, which is what matching a folder name wherever it appears needs.
- `shouldSkipCollectingAttachmentsReferencedByRawPath`
  - a safety net for attachments referenced by other plugins' non-standard syntaxes. When on, before collecting an attachment the plugin also scans every note's raw text for the attachment's path or file name; if a note references it in a format Obsidian does not index, the attachment is treated as still used and left in place (it is not moved or renamed). Default off. See [05 Collect attachments](<./05 Collect attachments.md>).

## Renames and deletions — moved to another plugin in 12.0.0

Renames and deletions are handled by **[Advanced Rename and Delete Handler](https://obsidian.md/plugins?id=advanced-rename-and-delete-handler)**, not by this plugin. Two plugins handling one rename corrupt links and move attachments twice, so exactly one plugin owns it, and these settings live there:

- `shouldHandleRenames`, `shouldHandleDeletions` (spelled `shouldDeleteOrphanAttachments` here before 12.0.0), `shouldRenameAttachmentFiles`, `shouldRenameAttachmentFolder`, `shouldRescueSharedAttachments`, `emptyFolderBehavior`, `treatAsAttachmentExtensions`, `notePriorities`, `includePaths` and `excludePaths`.

Upgrading offers to move whatever you had set into that plugin, once. Until you accept, your values are kept in `proposedRenameDeleteSettings` below and the offer returns; cancelling does not throw them away.

Five of those settings still matter to **this** plugin's own commands — Collect attachments, Delete unused attachments and Go to owning note all need to know what an attachment is, which paths to skip, which note owns a shared attachment and what to do with an emptied folder. This plugin reads them back from Advanced Rename and Delete Handler rather than keeping a second copy, so there is one place to set them.

Two things follow:

- **`includePaths` / `excludePaths` now scope both plugins.** Excluding a folder from rename handling also excludes it from this plugin's Collect attachments and Delete unused attachments.
- **This plugin needs Advanced Rename and Delete Handler, and does nothing without it.** While it is missing, disabled, or older than 1.2.0 — the version that first hands these values back — this plugin loads nothing, says why in a notice and in its settings tab, and installs it in one click. It finishes loading the moment the other plugin appears, with no restart. Installing it changes nothing on its own: its defaults do nothing until you turn renames or deletions on, and the values you had set here are offered in its migration dialog. This vault installs it for you on first open.

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
- `proposedRenameDeleteSettings`
  - the rename/delete values this plugin held before 12.0.0, waiting to be offered to Advanced Rename and Delete Handler. `null` once the migration is applied, and `null` on a fresh install, which is how the plugin knows never to offer a migration of values you never set. Managed by the plugin, not edited by hand.
