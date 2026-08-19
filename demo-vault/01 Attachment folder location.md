# Attachment folder location

The headline feature: **you** decide the folder each attachment is saved into, per note, using tokens. This vault ships with the plugin's default location setting:

```text
./assets/${noteFileName}
```

The `./` means "relative to the folder of the note you are editing", and `${noteFileName}` expands to the current note's name. So an attachment pasted here goes into a folder named after this note.

## Try it

1. Click somewhere in this note to put the cursor here.
2. Paste an image from your clipboard (or drag an image file into the editor). You supply the file - the demo cannot paste for you.
3. Look in the File Explorer: a folder like `assets/01 Attachment folder location/` now holds the file, and the inserted link points at it.

No image to hand? You can ask the plugin where a paste **would** go without pasting anything. The button calls the same function Obsidian calls when you paste, so the answer is the real one:

```code-button
---
caption: Where would a pasted image go?
---
await require('/demoSetup.ts').previewAttachmentPath(app);
```

Manual equivalent: paste an image and look at where it landed. Try it from a different note and the answer changes - that is `${noteFileName}` at work.

Paste another image into [02 Attachment file naming](<./02 Attachment file naming.md>) and notice it lands in a *different* per-note folder. That is `${noteFileName}` at work.

## Change the location

Open **Settings -> Community plugins -> Custom Attachment Location** and edit **Location for new attachments** (`attachmentFolderPath`). For example:

- `assets`
  - one shared folder (an absolute, vault-root path, because there is no leading `./`).
- `./attachments`
  - a folder next to each note.
- `./assets/${noteFileName}/${date:{momentJsFormat:'YYYY'}}`
  - per-note, then split by year.

Each is a button, since token patterns are exactly the kind of string that is easy to mistype. Press one, then ask where a paste would go:

```code-button
---
caption: One shared folder (`assets`)
---
await require('/demoSetup.ts').changeSettings(app, { attachmentFolderPath: 'assets' });
```

```code-button
---
caption: A folder next to each note (`./attachments`)
---
await require('/demoSetup.ts').changeSettings(app, { attachmentFolderPath: './attachments' });
```

```code-button
---
caption: Per-note, then split by year
---
await require('/demoSetup.ts').changeSettings(app, { attachmentFolderPath: './assets/${noteFileName}/${date:{momentJsFormat:\'YYYY\'}}' });
```

```code-button
---
caption: Where would a pasted image go now?
---
await require('/demoSetup.ts').previewAttachmentPath(app);
```

```code-button
---
caption: Restore this vault's default patterns
---
await require('/demoSetup.ts').restoreDefaultPatterns(app);
```

Manual equivalent for all of them: edit **Location for new attachments** in **Settings -> Community plugins -> Custom Attachment Location**.

See [03 Tokens and patterns](<./03 Tokens and patterns.md>) for the full token list.
