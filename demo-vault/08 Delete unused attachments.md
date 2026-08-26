# Delete unused attachments

Over time a note's attachment folder collects files the note no longer links to - an image you removed from the text, an older screenshot you replaced. **Custom Attachment Location** adds a **Delete unused attachments** command (and a right-click menu item on notes and folders) that moves those leftover files to the trash.

It is deliberately careful, because it deletes your data:

- It only ever touches files inside the note's own attachment folder.
- An attachment that is still referenced by the note is kept.
- An attachment that is still referenced by **another** note is kept - the same shared-attachment check the **Collect attachments** command uses (`excludePathsFromMultipleNotesCheck` applies here too).
- Everything it will remove is listed in a confirmation dialog **before** anything happens, and files go to the **trash** (recoverable), honoring your Obsidian "Deleted files" setting.

## Try it

Click the button below. It creates a note `Delete unused demo` whose attachment folder holds two images: `keep.png` (embedded in the note) and `orphan.png` (referenced by nothing).

```code-button
---
caption: Set up the delete-unused demo
---
const folderPath = 'assets/Delete unused demo';
const notePath = 'Delete unused demo.md';

if (!app.vault.getFolderByPath(folderPath)) {
  await app.vault.createFolder(folderPath);
}

// A tiny valid PNG header is enough for the demo.
const bytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer;
for (const name of ['keep.png', 'orphan.png']) {
  const path = `${folderPath}/${name}`;
  if (!app.vault.getFileByPath(path)) {
    await app.vault.createBinary(path, bytes);
  }
}

if (!app.vault.getFileByPath(notePath)) {
  await app.vault.create(notePath, '![[keep.png]]\n');
}

const note = app.vault.getFileByPath(notePath);
if (note) {
  await app.workspace.getLeaf(false).openFile(note);
}
```

Then:

1. In the File Explorer, right-click **`Delete unused demo`** and choose **Delete unused attachments in file** (the same command is in the Command Palette as **Delete unused attachments in current note**).
2. Read the confirmation dialog - it lists `assets/Delete unused demo/orphan.png` only.
3. Confirm. `orphan.png` moves to the trash; `keep.png` stays, because the note still embeds it.

If you add `![[orphan.png]]` to another note first and run the command again, `orphan.png` is kept - a shared attachment is never deleted.

## When you delete the note itself, or its folder

The command above is one half of the story. The other half is what happens to an attachment when you delete the **note** that owns it, or the whole **folder** that note lives in.

By default nothing special happens: the attachment goes wherever the deletion takes it, even if another note still embeds it. Two settings change that, and **both are off by default**:

- `shouldDeleteOrphanAttachments` - hands the delete path to the plugin at all. Nothing below works without it.
- `shouldRescueSharedAttachments` - with the first one on, an attachment another note still references is **moved into that surviving note's attachment folder** instead of being left behind or going down with the folder. It keeps its file name; only the folder is recomputed.

If exactly one note is left referencing the attachment, it wins outright. If several are, `notePriorities` (see [05 Collect attachments](<./05 Collect attachments.md>)) decides; a tie, or no match, leaves the attachment where it is rather than guessing.

### Try it

Click the button below. It creates `Shared A/` holding a note and `Shared A/attachments/shared.png`, plus `Shared B/` whose note embeds that same image.

```code-button
---
caption: Set up the shared-attachment deletion demo
---
const folderA = 'Shared A';
const folderB = 'Shared B';
const imagePath = `${folderA}/attachments/shared.png`;

for (const path of [folderA, `${folderA}/attachments`, folderB]) {
  if (!app.vault.getFolderByPath(path)) {
    await app.vault.createFolder(path);
  }
}

// A tiny valid PNG header is enough for the demo.
if (!app.vault.getFileByPath(imagePath)) {
  await app.vault.createBinary(imagePath, new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer);
}

for (const notePath of [`${folderA}/Note A.md`, `${folderB}/Note B.md`]) {
  if (!app.vault.getFileByPath(notePath)) {
    await app.vault.create(notePath, `![[${imagePath}]]\n`);
  }
}

const noteB = app.vault.getFileByPath(`${folderB}/Note B.md`);
if (noteB) {
  await app.workspace.getLeaf(false).openFile(noteB);
}
```

Then:

1. With both settings **off**, delete the `Shared A` folder. The image goes with it, and `Note B` is left with a broken embed - this is the default.
2. Undo the deletion (restore from trash), turn **both** settings on, and delete `Shared A` again. The image lands in `Shared B/attachments/` and `Note B` still renders it.

Related: [05 Collect attachments](<./05 Collect attachments.md>) reorganizes the attachments a note *does* use; this command removes the ones it no longer uses. All settings are explained in [06 Settings](<./06 Settings.md>).
