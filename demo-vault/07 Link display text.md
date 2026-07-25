[Docs](https://github.com/mnaoumov/obsidian-custom-attachment-location/)

# Link display text

By default, a link Obsidian inserts to an attachment shows the file path (or, for an embed, nothing readable). With **`shouldSetLinkDisplayTextToAttachmentFileName`** turned on, every link the plugin generates to an **attachment** uses the attachment's base name (the file name without its extension) as the visible display text - so `report-2026.pdf` shows up as `report-2026` instead of a long path.

Notes are deliberately left alone: a link from one note to another keeps Obsidian's normal display text. And if you provide an explicit alias, or the image has a cached size, that wins over the base-name default.

## Try it

1. Open **Settings -> Community plugins -> Custom Attachment Location** and turn on **Set link display text to attachment file name**.
2. Open a note and drag or paste a non-image attachment (for example a PDF) into it - you supply the file.
3. Look at the inserted link: it now reads `[[.../report-2026.pdf|report-2026]]`, showing `report-2026` as the display text.
4. Insert a link to another **note** and confirm its display text is unchanged - the setting only affects attachments.

Relevant setting: `shouldSetLinkDisplayTextToAttachmentFileName` (see [[06 Settings]]).
