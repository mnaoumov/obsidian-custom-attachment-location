# Delete unused attachments

Over time a note's attachment folder collects files the note no longer links to - an image you removed from the text, an older screenshot you replaced. **Custom Attachment Location** adds a **Delete unused attachments** command (and a right-click menu item on notes and folders) that moves those leftover files to the trash.

There are two scopes:

- **Delete unused attachments in current note** (also a right-click item on a note or a folder) - only what that note, or every note under that folder, no longer uses.
- **Delete unused attachments in entire vault** - the same sweep over every note in the vault.

They are separate commands rather than one command with a scope option, so a hotkey or a muscle-memory palette entry bound to the per-note one can never turn into a whole-vault deletion.

The vault-wide sweep reads every note and looks up the backlinks of every attachment it meets, which takes minutes on a large vault; a progress notice reports where it is and lets you cancel. Nothing is deleted until the scan has finished and you have confirmed.

It is deliberately careful, because it deletes your data:

- It only ever touches files inside the note's own attachment folder, unless you turn on **Find attachments no note owns** (see below).
- An attachment that is still referenced by the note is kept.
- An attachment that is still referenced by **another** note is kept - the same shared-attachment check the **Collect attachments** command uses (`excludePathsFromMultipleNotesCheck` applies here too).
- A folder listed under **Attachment unit folders** is one attachment, and is judged as a whole rather than file by file - see below.
- A confirmation dialog **before** anything happens states **how many** attachments will go, then names them - the first 50, and a count of the rest, because vault-wide the list can run to thousands and a wall of paths is not something you can weigh.
- Files go to the **trash** (recoverable), honoring your Obsidian "Deleted files" setting.
- Notes under an ignored path are skipped, on both scopes.

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

## Attachment unit folders are deleted whole

Some attachments are really a folder: a page saved from a browser sits next to a `_files/` folder holding its images and stylesheets, a drawing sits next to the images it references. Listing such a folder under **Attachment unit folders** (`attachmentUnitFolderPaths`) tells the plugin it is **one attachment** - see [05 Collect attachments](<./05 Collect attachments.md>), where the same setting makes the whole folder travel together.

This command reads that same designation, and it changes the question it asks. Instead of *"does anything reference this file?"*, per file, it asks once per folder:

> Does anything **outside** the folder reference **anything inside** it?

- **No** - the whole folder goes to the trash, everything in it included.
- **Yes** - the whole folder stays, including files nothing references. A unit that travels as one attachment is deleted as one too; removing the unreferenced half of a folder that is still in use is exactly the broken attachment the setting exists to prevent.

The **outside** part is what makes it work. A saved page's `.html` links its own images, and a drawing embeds its own; without discounting those internal links every such folder would look permanently in use and could never be cleaned up. Links between files in the same unit folder are the attachment describing itself, so they do not count.

Two things it will not do:

- If a real note lives inside the folder, the folder is left alone entirely and its files go back to being judged one at a time. An attachment sweep never puts a note in the trash on your behalf. (A `.excalidraw.md`, or anything else listed in `treatAsAttachmentExtensions`, is an attachment for this purpose, not a note.)
- The confirmation dialog lists **folders** separately from files and says outright that each one goes with everything inside it. A pattern can designate a large folder, so this is the point at which to read what is about to happen.

### Try it

Click the button below. It creates a note whose attachment folder holds two unit folders: `page_files/` (a drawing plus the image it embeds - nothing outside points at either) and `kept_files/` (an image the note embeds, plus a sibling nothing references).

```code-button
---
caption: Set up the unit-folder delete demo
---
const folderPath = 'assets/Unit folder demo';
const notePath = 'Unit folder demo.md';

for (const path of [folderPath, `${folderPath}/page_files`, `${folderPath}/kept_files`]) {
  if (!app.vault.getFolderByPath(path)) {
    await app.vault.createFolder(path);
  }
}

// A tiny valid PNG header is enough for the demo.
const bytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer;
for (const path of [`${folderPath}/page_files/img.png`, `${folderPath}/kept_files/kept.png`, `${folderPath}/kept_files/orphan.png`]) {
  if (!app.vault.getFileByPath(path)) {
    await app.vault.createBinary(path, bytes);
  }
}

// The drawing embeds its own sibling. That is the unit describing itself.
const drawingPath = `${folderPath}/page_files/page.excalidraw.md`;
if (!app.vault.getFileByPath(drawingPath)) {
  await app.vault.create(drawingPath, `![[${folderPath}/page_files/img.png]]\n`);
}

if (!app.vault.getFileByPath(notePath)) {
  await app.vault.create(notePath, `![[${folderPath}/kept_files/kept.png]]\n`);
}

const note = app.vault.getFileByPath(notePath);
if (note) {
  await app.workspace.getLeaf(false).openFile(note);
}
```

Then:

1. Add both `assets/Unit folder demo/page_files` and `assets/Unit folder demo/kept_files` to **Attachment unit folders** in the settings tab.
2. Run **Delete unused attachments in current note** on `Unit folder demo`.
3. The dialog names **`assets/Unit folder demo/page_files`** as a folder going whole, and does not mention `kept_files` at all.
4. Confirm. `page_files/` is gone entirely - `img.png` with it, even though the drawing beside it embedded that image. `kept_files/` is untouched, `orphan.png` included.

Remove both entries from **Attachment unit folders** and repeat with a fresh copy to see the difference: now `img.png` is kept (the drawing still references it) while the drawing and `orphan.png` are trashed individually - each folder left half-empty.

## Attachments no note owns

Everything above starts from a **note**: the sweep reads a note, works out where that note's attachments belong, and looks in there. Which means there is one thing it structurally cannot find - **an attachment folder whose note is gone**.

Delete `My note.md` and its `assets/My note/` folder stays behind. Nothing in the vault points at that folder any more, no note resolves to it, so no scan ever opens it. Its files sit there permanently, and even `Delete unused attachments in entire vault` walks straight past them. This is not only about deleting a note in Obsidian: a vault synced by Syncthing, git or git-annex has notes removed by the sync, so the plugin never sees a deletion event either and the settings on the next page do not fire.

`orphanAttachmentScanMode` adds a second pass for exactly that case. It has three settings and is **off by default**:

- **None** - as above. Attachments are found only through the notes that own them.
- **Listed paths** - also check every file under the paths in `orphanAttachmentScanPaths`, whether or not a note leads there.
- **Entire vault** - also check every file in the vault that is not a note.

Two things to understand before turning it on.

**You have to say where to look.** The plugin cannot work it out. `attachmentFolderPath` is a pattern, and a pattern only runs one way: `${prompt}` and `${random}` throw away the very value the folder name was built from, and two notes can resolve to the same folder. There is no "attachment root" to enumerate, so **Listed paths** takes the folders from you. If your attachments all live in folders called `!!files`, that is `/\/!!files\//` - a regular expression, because a plain entry is anchored at the vault root.

**"Unused" gets a wider meaning.** Without a note in the picture, the only remaining evidence is the link graph: a file with no backlinks is unused. Under **Entire vault** that includes a PDF you dropped in a folder and never linked, which you may be keeping on purpose. The confirmation dialog still names everything first, and a path excluded in **Advanced Rename and Delete Handler** is skipped, but this is the mode to point at a folder you trust rather than the whole vault.

It applies to the **whole-vault command only**. The per-note and per-folder commands do not run it, deliberately: this pass concludes that nothing references a file, and that conclusion is only safe from a scan that actually read every note in the vault. A canvas outside a selected folder could be the one thing embedding a file inside it - and a canvas's embeds are not in Obsidian's backlink index at all, which is why the plugin reads them out of the canvas file itself.

### Try it

Click the button below. It creates `Ownerless demo/` holding two attachment folders: `Kept note/` (whose note exists and embeds its image) and `Gone note/` (whose note does **not** exist - the case this is about).

```code-button
---
caption: Set up the ownerless-attachment demo
---
const rootFolder = 'Ownerless demo';
const notePath = 'Kept note.md';

for (const path of [rootFolder, `${rootFolder}/Kept note`, `${rootFolder}/Gone note`]) {
  if (!app.vault.getFolderByPath(path)) {
    await app.vault.createFolder(path);
  }
}

// A tiny valid PNG header is enough for the demo.
const bytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer;
for (const path of [`${rootFolder}/Kept note/kept.png`, `${rootFolder}/Gone note/lost.png`]) {
  if (!app.vault.getFileByPath(path)) {
    await app.vault.createBinary(path, bytes);
  }
}

if (!app.vault.getFileByPath(notePath)) {
  await app.vault.create(notePath, `![[${rootFolder}/Kept note/kept.png]]\n`);
}

const note = app.vault.getFileByPath(notePath);
if (note) {
  await app.workspace.getLeaf(false).openFile(note);
}
```

Then:

1. Run **Delete unused attachments in entire vault** as it stands. It reports **no unused attachments**: `lost.png` is invisible to it, because no note leads to `Gone note/`.
2. In the settings tab, on the **Path** page, set **Find attachments no note owns** to **Listed paths** and add `Ownerless demo` to **Paths to look in**.
3. Run the command again. Now the dialog names `Ownerless demo/Gone note/lost.png` - and does not mention `kept.png`, which its note still embeds.

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
