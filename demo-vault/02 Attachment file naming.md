# Attachment file naming

Besides the folder, the plugin also controls the **file name** given to a new attachment. This vault ships with the plugin's default naming setting (`generatedAttachmentFileName`):

```text
file-{{date:{momentJsFormat:'YYYYMMDDHHmmssSSS'}}}
```

So a pasted image is saved as something like `file-20251231093015123.png` instead of Obsidian's default `Pasted image 20251231093015`.

## Try it

1. Paste an image into this note.
2. Check the created file name in the folder from [01 Attachment folder location](<./01 Attachment folder location.md>) - it starts with `file-` followed by a timestamp.

No image to hand? The button saves a sample image as an attachment of this note, under the folder and the name a paste would give it, and names the file it saved. It puts this vault's patterns back first, in case another note changed them:

```code-button
---
caption: Restore this vault's patterns and save a sample image
---
const demoSetup = require('/demoSetup.ts');
await demoSetup.restoreDefaultPatterns(app);
await demoSetup.saveSampleAttachment(app, { kind: 'image' });
```

Manual equivalent: paste an image into this note and look at the file it created.

## Make the name your own

Open **Settings -> Community plugins -> `Custom Attachment Location`** and edit **Generated attachment file name**. A few ideas:

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
caption: Save a sample image with the current pattern
---
await require('/demoSetup.ts').saveSampleAttachment(app, { kind: 'image' });
```

```code-button
---
caption: Restore this vault's default patterns
---
await require('/demoSetup.ts').restoreDefaultPatterns(app);
```

Manual equivalent: edit **Generated attachment file name** in **Settings -> Community plugins -> `Custom Attachment Location`**.

These patterns apply to attachments saved through Obsidian itself — a paste, a drop, an import. A plugin that writes an attachment into the vault under a name of its own instead bypasses them; set `renameAttachmentsCreatedByOtherPluginsMode` to have those files moved and renamed too, just after they appear — for every plugin, or for a named set in either polarity.

**An image pasted into an `Excalidraw` drawing is one of those files.** `Excalidraw` asks where an attachment of the drawing belongs, keeps only the folder, and saves the image under its own `Pasted Image <date>.png`. With `renameAttachmentsCreatedByOtherPluginsMode` on, the image gets the file name your patterns generate — a `{{prompt}}` pattern asks you for it — in the folder the drawing's own patterns resolve to. That holds although the drawing is listed in `treatAsAttachmentExtensions`, as `.excalidraw.md` is by default: the drawing still owns the images it shows.

The drawing keeps showing the image under its new name, whether `Excalidraw`'s **Compress `Excalidraw` JSON** setting is on or off. `Excalidraw` records each image as an ordinary `[[link]]` line under `## Embedded Files`, outside the compressed data, so Obsidian updates that line like any other link.

Related settings you can explore: `renamedAttachmentFileName`, `shouldRenameAttachmentFiles`, `attachmentRenameMode`, `renameAttachmentsCreatedByOtherPluginsMode`, `otherPluginIdsForAttachmentRename`, `duplicateNameSeparator`, and `collectedAttachmentFileName`. Every key is described in [06 Settings](<./06 Settings.md>). The tokens themselves live in [03 Tokens and patterns](<./03 Tokens and patterns.md>).

## Sidecar files

A detached signature belongs beside the document it signs. When `document.html` and `document.html.p7s` are pasted or dropped together, the plugin generates the document's name once, for example `k3x9q2m7v1a8.html`, then saves the companion as `k3x9q2m7v1a8.html.p7s`. Import order does not matter. A unique same-stem companion such as `video.srt` follows `video.mkv` as well. The mobile share sheet uses a separate naming path and does not support pairing yet.

`sidecarExtensions` (**Sidecar extensions**) defaults to `p7s`, `sig`, `asc`, `srt` and `vtt`. Entries accept an optional leading dot and ignore case; an empty list disables pairing. Full-name matches take priority. Several possible bases are ambiguous: the sidecar keeps its own name, with a notice, just as when its base is missing. File names themselves must match exactly, including case.

Renaming or moving a base file inside Obsidian carries its companions, including ones no note links to. An occupied companion destination refuses the group move before changing the base. Importing paired files together is the most reliable way to retain their relationship; batch matches are scoped to their source directory. A signature imported later can use a unique base in the note's destination folder, including its remembered arrival name. If no such base can be established, its own name is kept. Files imported as a group keep their bytes, so image conversion cannot invalidate a detached signature. Naming alone does not check a signature's validity.

```code-button
---
caption: Import an HTML document and its companion with one random name
---
await require('/demoSetup.ts').saveSidecarDemo(app);
```

The button creates a demonstration pair under `Materials/02 Attachment file naming/Sidecars`, links both files, and opens its note. The `.p7s` contains sample text, not a real digital signature. Rename the HTML file in the File explorer: the `.p7s` follows it. The **Restore this vault's default patterns** button above restores the naming pattern afterward.

Manual equivalent: enable attachment renaming for all files, set **Generated attachment file name** to `{{random}}`, and drag a document and its signature into a note together.

**Delete unused attachments** keeps a paired group when any member is still used, so an unlinked signature stays beside its linked document. A group is offered for deletion only when all its members are unused within the selected scope. Ambiguous and orphan sidecars are judged independently.

Copy modes in **Collect attachments** and **Move attachment to proper folder** copy unlinked companions and chained signatures beside the base's actual new name, including a collision suffix. A reused identical base also reuses byte-identical companions. A conflicting companion destination refuses the copy and rolls back newly created files; existing files remain untouched.
