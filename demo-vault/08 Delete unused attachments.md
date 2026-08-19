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

Related: [05 Collect attachments](<./05 Collect attachments.md>) reorganizes the attachments a note *does* use; this command removes the ones it no longer uses. All settings are explained in [06 Settings](<./06 Settings.md>).
