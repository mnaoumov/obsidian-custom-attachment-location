[Docs](https://github.com/mnaoumov/obsidian-custom-attachment-location/)

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

Paste another image into [[02 Attachment file naming]] and notice it lands in a *different* per-note folder. That is `${noteFileName}` at work.

## Change the location

Open **Settings -> Community plugins -> Custom Attachment Location** and edit **Location for new attachments** (`attachmentFolderPath`). For example:

- `assets` - one shared folder (an absolute, vault-root path, because there is no leading `./`).
- `./attachments` - a folder next to each note.
- `./assets/${noteFileName}/${date:{momentJsFormat:'YYYY'}}` - per-note, then split by year.

See [[03 Tokens and patterns]] for the full token list.
