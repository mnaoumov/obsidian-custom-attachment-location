# Attachment file naming

Besides the folder, the plugin also controls the **file name** given to a new attachment. This vault ships with the plugin's default naming setting (`generatedAttachmentFileName`):

```text
file-{{date:{momentJsFormat:'YYYYMMDDHHmmssSSS'}}}
```

So a pasted image is saved as something like `file-20251231093015123.png` instead of Obsidian's default `Pasted image 20251231093015`.

## Try it

1. Paste or drag an image into this note (you supply the file).
2. Check the created file name in the folder from [01 Attachment folder location](<./01 Attachment folder location.md>) - it starts with `file-` followed by a timestamp.

## Make the name your own

Open **Settings -> Community plugins -> Custom Attachment Location** and edit **Generated attachment file name**. A few ideas:

- `{{noteFileName}}-{{date:{momentJsFormat:'YYYYMMDD'}}}`
  - name after the note plus the date.
- `{{originalAttachmentFileName}}`
  - keep the file's original name (handy for dragged files).
- `{{prompt}}`
  - ask you for a name each time, with a live preview of the file.

The first two are buttons; `{{prompt}}` is left to set by hand, since it interrupts every paste until you change it back:

```code-button
---
caption: Name after the note plus the date
---
await require('/demoSetup.ts').changeSettings(app, { generatedAttachmentFileName: '{{noteFileName}}-{{date:{momentJsFormat:\'YYYYMMDD\'}}}' });
```

```code-button
---
caption: Keep the original file name
---
await require('/demoSetup.ts').changeSettings(app, { generatedAttachmentFileName: '{{originalAttachmentFileName}}' });
```

```code-button
---
caption: Where would a pasted image go, and what would it be called?
---
await require('/demoSetup.ts').previewAttachmentPath(app);
```

```code-button
---
caption: Restore this vault's default patterns
---
await require('/demoSetup.ts').restoreDefaultPatterns(app);
```

Manual equivalent: edit **Generated attachment file name** in **Settings -> Community plugins -> Custom Attachment Location**.

These patterns apply to attachments saved through Obsidian itself — a paste, a drop, an import. A plugin that writes an attachment into the vault under a name of its own instead bypasses them; set `renameAttachmentsCreatedByOtherPluginsMode` to have those files moved and renamed too, just after they appear — for every plugin, or for a named set in either polarity.

**An image pasted into an Excalidraw drawing is one of those files.** Excalidraw asks where an attachment of the drawing belongs, keeps only the folder, and saves the image under its own `Pasted Image <date>.png`. With `renameAttachmentsCreatedByOtherPluginsMode` on, the image gets the file name your patterns generate — a `{{prompt}}` pattern asks you for it — in the folder the drawing's own patterns resolve to. That holds although the drawing is listed in `treatAsAttachmentExtensions`, as `.excalidraw.md` is by default: the drawing still owns the images it shows.

The drawing keeps showing the image under its new name, whether Excalidraw's **Compress Excalidraw JSON** setting is on or off. Excalidraw records each image as an ordinary `[[link]]` line under `## Embedded Files`, outside the compressed data, so Obsidian updates that line like any other link.

Related settings you can explore: `renamedAttachmentFileName`, `shouldRenameAttachmentFiles`, `attachmentRenameMode`, `renameAttachmentsCreatedByOtherPluginsMode`, `otherPluginIdsForAttachmentRename`, `duplicateNameSeparator`, and `collectedAttachmentFileName`. Every key is described in [06 Settings](<./06 Settings.md>). The tokens themselves live in [03 Tokens and patterns](<./03 Tokens and patterns.md>).
