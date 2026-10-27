# Collect attachments

Changing your location or naming pattern only affects *new* attachments. To bring **existing** attachments into line with the current settings, the plugin adds **Collect attachments** commands. They move each attachment referenced by a note into the folder (and under the name) your patterns would produce today.

## Commands

Open the Command Palette (`Ctrl`/`Cmd` + `P`) and search for *`Custom Attachment Location`*:

- **Collect attachments in current note**
  - reorganizes only the attachments used by the active note.
- **Collect attachments in current folder**
  - every note in the active note's folder.
- **Collect attachments in entire vault**
  - the whole vault at once.

There is also **Move attachment to proper folder**, which relocates a single attachment file to where the settings say it belongs.

## Collecting automatically

Turn on **Collect attachments automatically** (`shouldCollectAttachmentsAutomatically`) and the plugin collects a note's attachments every time the note changes, as if you had run **Collect attachments in current note** on it. Nothing happens while the link suggester is open, so a half-typed link is never acted on. It moves files without asking, on every save, so it is off by default.

## Try it

Every demo on this page works the same way. A set-up button creates a folder of its own under `Materials/05 Collect attachments/`, writes the notes and images the demo needs, sets every setting the demo depends on, and opens the demo's note. The buttons after it each do one step, and each one ends with a notice listing what the demo folder holds now, so you can watch the files move without hunting for them in the File Explorer. Pressing a set-up button again starts its demo over from scratch. The demos change settings that affect the whole vault, so the button at the end of this page puts them all back.

This one creates `Collect demo/`: a note, `Collect demo`, embedding `loose/image.png` - an attachment sitting outside the folder the settings name.

```code-button
---
caption: Set up the collect demo
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'basic');
```

Collect it. The image moves to `assets/Collect demo/image.png`, the folder **Location for new attachments** (`./assets/{{noteFileName}}`) gives the note.

```code-button
---
caption: Collect the attachments of Collect demo
---
await require('/demoSetup.ts').collectInDemo(app, 'basic');
```

Now change **Location for new attachments** to `./attachments` and collect again. The image follows the new pattern to `attachments/image.png`.

```code-button
---
caption: Change the location to ./attachments and collect again
---
const demoSetup = require('/demoSetup.ts');
await demoSetup.changeSettings(app, { attachmentFolderPath: './attachments' });
await demoSetup.collectInDemo(app, 'basic');
```

Manual equivalent: create a note embedding an image kept outside its attachment folder, open it and run **Collect attachments in current note**, then edit **Location for new attachments** in **Settings -> Community plugins -> `Custom Attachment Location`** and run the command again. **Collect attachments in current folder** and **Collect attachments in entire vault** do the same for every note they reach.

Relevant settings: `shouldRenameCollectedAttachments`, `collectedAttachmentFileName`, `collectAttachmentUsedByMultipleNotesMode`, and `moveAttachmentToProperFolderUsedByMultipleNotesMode` control how collecting handles renaming and attachments shared by several notes; `excludePathsFromMultipleNotesCheck` lets you ignore certain notes (e.g. `.excalidraw` drawings) from that shared-attachment check, and `excludeExtensionsFromMultipleNotesCheck` exempts whole attachment file types from it. All keys are explained in [06 Settings](<./06 Settings.md>).

## A separate destination for collected attachments

By default collecting puts an attachment wherever a *new* attachment would go - both read **Location for new attachments** (`attachmentFolderPath`). **Collected attachment folder path** (`collectedAttachmentFolderPath`) splits the two apart. It is empty by default, and empty means "use the location for new attachments", so nothing changes until you fill it in.

This is what makes a portable export possible without re-configuring the plugin twice per note. Keep new attachments in a shared working folder and collect into a folder beside the note:

- **Location for new attachments**: `_Attachments`
- **Collected attachment folder path**: `./{{noteFileName}}.assets`

Running **Collect attachments in current note** then gathers that one note's attachments into `Example Note.assets/` next to `Example Note.md`, while pasting a new image still puts it in `_Attachments`. Convert the embeds to relative Markdown paths afterwards and the `.md` + `.assets` pair opens correctly outside Obsidian.

Two things worth knowing:

- It accepts the same patterns and tokens as the location for new attachments, including `./` for a path relative to the note's folder.
- **Move attachment to proper folder** is not affected - it keeps using the location for new attachments, because it answers where an attachment belongs rather than where an export gathers it.

### Try it

The set-up button creates `Destination demo/` with **Location for new attachments** set to its `_Attachments` folder and **Collected attachment folder path** empty. Its note, `Example Note`, embeds `_Attachments/image.png`, as if you had pasted it there.

```code-button
---
caption: Set up the destination demo
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'destination');
```

Collect the note. The image stays in `_Attachments`, because both settings resolve to the same folder.

```code-button
---
caption: Collect with no destination of its own
---
await require('/demoSetup.ts').collectInDemo(app, 'destination');
```

Set **Collected attachment folder path** to `./{{noteFileName}}.assets` and collect again. The image moves into `Example Note.assets/` beside the note.

```code-button
---
caption: Give collecting its own destination and collect again
---
const demoSetup = require('/demoSetup.ts');
await demoSetup.changeSettings(app, { collectedAttachmentFolderPath: './{{noteFileName}}.assets' });
await demoSetup.collectInDemo(app, 'destination');
```

Paste another image. It still lands in `_Attachments`, untouched by the collect destination. The button saves a sample image under the folder and the name a paste would get.

```code-button
---
caption: Save a new image the way a paste would
---
await require('/demoSetup.ts').pasteIntoDestinationDemo(app);
```

Manual equivalent: set the two settings in **Settings -> Community plugins -> `Custom Attachment Location`**, paste an image into a note, and run **Collect attachments in current note** after each change.

## Original attachment names

A collect that renames (`shouldRenameCollectedAttachments`) builds the new name from `collectedAttachmentFileName`, and a pattern such as `{{noteFileName}}-{{originalAttachmentFileName}}` reads the name the attachment **arrived with**. The plugin remembers that name when it saves a pasted, dropped, shared or downloaded attachment, and keeps it through every rename and move Obsidian reports. So collecting `img.png` into `Note` gives `Note-img.png`, and collecting again leaves it there, instead of making it `Note-Note-img.png`. `{{attachmentFileName}}` is there for a pattern that wants the current name instead; both are in [09 Token reference](<./09 Token reference.md#two-families-the-attachment-as-it-is-now-and-as-it-arrived>).

An attachment the plugin never saw arrive has no remembered name: one that predates the plugin, one renamed outside Obsidian, one synced from another device. Its current name is used, it is remembered from then on, and one notice per collect says how many there were. Its **Details** button lists them. `shouldWarnWhenOriginalAttachmentNameIsUnknown` turns that notice off.

The names and optional original source paths sync between devices through Markdown records in `Plugin data/obsidian-custom-attachment-location/original-attachment-names-v1/`. Keep this folder included in your sync tool. You can add `Plugin data` to Obsidian's **Excluded files** to hide these records from search, graph and the quick switcher. The earliest arrival name wins when devices record the same attachment; deliberate name edits still replace it. Existing `original-attachment-names.json` records migrate automatically, and that old file stays untouched as a recovery copy. Three commands look after the records:

- **Show original attachment names**
  - lists every remembered name as `current path → original name`, sorted by path, with a filter box, the totals, a *missing* badge on a path with no file any more, and **Copy as CSV**. Each row can be edited, forgotten, or set to the file's current name, and several selected rows can be forgotten or set at once. That is how a pasted screenshot remembered as `Pasted image 20250101120000.png`, which you have since renamed to something meaningful, gets the meaningful name to build on.
- **Prune original attachment names**
  - removes the remembered names whose file no longer exists, after listing them. The same dialog has **Forget all**, which asks once more before throwing every name away.
- **Remember current name as original**
  - in an attachment's file menu, the multi-file menu, and the command palette for the active file: makes the current name the one patterns build on.

Manual walkthrough: set `collectedAttachmentFileName` to `{{noteFileName}}-{{originalAttachmentFileName}}` and turn on `shouldRenameCollectedAttachments`. Paste an image into a note, run **Collect attachments in current note** twice, and the image keeps the name the first collect gave it. Then run **Show original attachment names** to see the name it arrived with.

Right-click an attachment in the file explorer, or a link to that attachment, for **Copy original file name** and **Copy original path**. Each action copies its stored value exactly and stays visible but disabled when that value is unknown. Neither substitutes the attachment's current name or path. The original path is the source path exposed by the import, when available; older records and pathless clipboard images have no source path. These optional paths are stored alongside the original names, follow vault moves, and are removed when their records are forgotten or deleted. Remembering a different original name does not change a recorded source path. Obsidian's own path-copy actions continue to describe the current file.

Manual copy walkthrough: turn on **All** attachment renaming and choose a generated name different from the incoming name. Drop a PDF from a file manager into a note. Use each original-metadata copy action from the attachment's file menu and from its note link, then paste into a plain text editor: the results should be the source file's name and source path. A pathless clipboard image enables the original-name action only. An attachment with neither value recorded shows both actions disabled.

## Safety net for non-standard references

The plugin only sees attachment references that Obsidian indexes - traditional `[[wikilink]]` / `![](markdown)` embeds. If another plugin renders images through its own syntax (a raw `<img src="...">`, a custom code block, an image-slider list, etc.), those references are invisible to collecting, so an attachment used only that way could be moved to an unexpected place and later lost.

Turn on **Skip collecting attachments referenced by a raw path** (`shouldSkipCollectingAttachmentsReferencedByRawPath`) to guard against that: before moving an attachment, the plugin scans every note's raw text for the attachment's path or file name and, if it finds a non-indexed reference, leaves the attachment in place instead of collecting it.

### Try it

The set-up button creates `Raw path demo/` with an image and two notes: `raw-ref` shows the image through raw HTML, an `<img src=...>` tag Obsidian does not index, and `Embed` embeds it the ordinary way. The setting starts **off**.

```code-button
---
caption: Set up the raw-path demo with the setting off
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'rawPath');
```

Collect `Embed`. The image moves to `assets/Embed/`, even though `raw-ref` still points at the old path, so the raw HTML now shows nothing.

```code-button
---
caption: Collect Embed with the setting off
---
await require('/demoSetup.ts').collectInDemo(app, 'rawPath');
```

Start over with the setting **on** and collect again. The image is left where it is, and a notice reports that it is referenced by a raw path.

```code-button
---
caption: Start over with the setting on
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'rawPath', { shouldSkipCollectingAttachmentsReferencedByRawPath: true });
```

```code-button
---
caption: Collect Embed with the setting on
---
await require('/demoSetup.ts').collectInDemo(app, 'rawPath');
```

Manual equivalent: create the two notes, run **Collect attachments in current note** in `Embed`, then toggle **Skip collecting attachments referenced by a raw path** in **Settings -> Community plugins -> `Custom Attachment Location`** and repeat with a fresh copy.

## Identical copies

Collecting the same image from two notes into one folder normally leaves two files, `image.png` and `image 1.png`, which differ only by the suffix. Turn on **Deduplicate identical attachments** (`shouldDeduplicateIdenticalAttachments`) to keep one: when the destination already holds a file with exactly the same content, every link to the incoming attachment is pointed at that file - in note bodies, in frontmatter and in canvases - and the incoming attachment is moved to the trash.

The files are compared by content, not by name. Two different images that happen to share a name still get the suffix, so a note is never pointed at a different picture. The same applies to **Move attachment to proper folder** and to attachments other plugins create.

### Try it

The set-up button creates `Dedupe demo/` holding the same image twice under the same name, `a/image.png` and `b/image.png`, each embedded from its own note. It sets **Location for new attachments** to the demo's `_Attachments` folder, leaves **Rename collected attachments** off so the names survive, and starts with the setting **off**.

```code-button
---
caption: Set up the dedupe demo with the setting off
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'dedupe');
```

Collect both notes. `_Attachments` ends up holding `image.png` and `image 1.png`.

```code-button
---
caption: Collect Note A and Note B with the setting off
---
await require('/demoSetup.ts').collectInDemo(app, 'dedupe', ['a/Note A.md', 'b/Note B.md']);
```

Start over with the setting **on** and collect both again. `_Attachments` holds one `image.png`, both notes embed it, and the second copy is in the trash.

```code-button
---
caption: Start over with deduplication on
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'dedupe', { shouldDeduplicateIdenticalAttachments: true });
```

```code-button
---
caption: Collect Note A and Note B with deduplication on
---
await require('/demoSetup.ts').collectInDemo(app, 'dedupe', ['a/Note A.md', 'b/Note B.md']);
```

Manual equivalent: make the two copies and their notes, run **Collect attachments in current note** in each note, then toggle **Deduplicate identical attachments** in **Settings -> Community plugins -> `Custom Attachment Location`** and repeat with fresh copies.

## Attachments that are really a folder

Some attachments are a directory tree rather than a file: a page saved from a browser sits next to a `_files/` folder holding its images and stylesheets, and a drawing sits next to the pictures it references. Collecting moves the file that was linked and leaves its siblings behind, so the attachment arrives intact-looking but blank.

List those folders under **Attachment unit folders** (`attachmentUnitFolderPaths`) and the whole folder travels whenever collecting moves any attachment inside it. The folder lands in the note's attachment folder under its own name, so its internal shape - and the relative links inside it - keep working.

Entries use the same vocabulary as the include / exclude path settings, and every form ignores case:

- a plain entry is a path from the vault root, and matches that folder and everything inside it, e.g. `Archive/Old`;
- an entry holding `*`, `?` or `[` is a glob: `*` matches within a name, `**` across folders, `?` one character and `[abc]` one of a set. A glob without a `/` matches a file or folder *name* wherever it appears, one with a `/` is matched from the vault root, and a trailing `/` matches folders only. To designate every `_files` folder in the vault, write `*_files/`;
- an entry shaped `/pattern/flags` is a regular expression tested against the full path, e.g. `/(^|\/)[^/]+_files(\/|$)/`.

To use `*`, `?` or `[` literally in a path, put a backslash before it: `Notes \[old\]`.

Two things worth knowing:

- When folders are nested and both are designated, the **outermost** one travels. Moving the inner one would tear the outer tree in half, which is the failure this setting exists to prevent.
- An attachment inside such a folder that is referenced by several notes is left where it is rather than copied, because copying the single file out of the folder produces exactly the broken attachment the setting prevents.

### Try it

The set-up button creates `Unit folder demo/` with `saved-page/page_files/logo.png` and `saved-page/page_files/style.css`, and a note, `Saved page`, embedding only `logo.png`. **Attachment unit folders** starts empty.

```code-button
---
caption: Set up the unit-folder demo with the setting empty
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'unitFolder');
```

Collect the note. Only `logo.png` moves, to `assets/Saved page/`, and `style.css` is stranded.

```code-button
---
caption: Collect Saved page with no unit folder
---
await require('/demoSetup.ts').collectInDemo(app, 'unitFolder');
```

Start over with `saved-page/page_files` listed under **Attachment unit folders** and collect again. The whole `page_files` folder moves to `assets/Saved page/page_files/`, `style.css` included.

```code-button
---
caption: Start over with page_files as a unit folder
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'unitFolder', { attachmentUnitFolderPaths: ['Materials/05 Collect attachments/Unit folder demo/saved-page/page_files'] });
```

```code-button
---
caption: Collect Saved page with the unit folder
---
await require('/demoSetup.ts').collectInDemo(app, 'unitFolder');
```

Manual equivalent: create the two files and the note, run **Collect attachments in current note**, then add `Materials/05 Collect attachments/Unit folder demo/saved-page/page_files` to **Attachment unit folders** in **Settings -> Community plugins -> `Custom Attachment Location`** and repeat with a fresh copy.

## When several notes reference the same attachment

An attachment referenced by more than one note has no single correct home, so collecting falls back to **Collect attachment used by multiple notes mode** - skip it, copy it, cancel, or ask.

**Note priorities** (`notePriorities`) lets you answer the question once instead. List the kinds of note in order, highest priority first, and the winning note takes the attachment:

- an entry starting with a dot is a file extension, e.g. `.md`;
- an entry starting with `property:` matches a frontmatter property, optionally with a value, e.g. `property:excalidraw-plugin` or `property:type=drawing`;
- anything else is a path from the vault root, or a `/regular expression/`.

When a note matches several entries, the **longest** one decides its rank. That is what makes the common case work: `drawing.excalidraw.md` also ends with `.md`, so without it a list of `.md` then `.excalidraw.md` would tie instead of putting the plain note first.

Five things worth knowing:

- If no entry matches, or if the best entry matches several of the referencing notes, nothing is decided here and the mode setting handles it as before. A tie is never broken silently. **The dialog that then appears says which of the three it was** - the list is empty, nothing matched, or several notes matched equally - so you can tell a list you never configured from one that simply did not apply.
- **The dialog lists only the notes sharing the best rank.** A note the list deliberately ranked lower cannot break the tie between the ones above it, so it is left out rather than offered as if it could. When the list decides nothing at all - it is empty, or it matches none of them - every referencing note is listed, because nothing has ruled any of them out. The console message names exactly the same notes as the dialog.
- The winner does not have to be the note you ran the command on. Collecting from a drawing can hand the image to a markdown note that outranks it. That is the point of the setting, and why it is empty by default.
- Once a single note wins, the collect is settled, so no shared-attachment dialog appears. If the winner **already** holds the attachment there is simply nothing to move - exactly as for an attachment only one note references.
- **When the winner is not the note you ran the command on, a notice names the notes that outrank it**, each as a link you can open. Every note above yours is listed, not only the winner, because the question it answers is who outranks you rather than who won. The attachment still moves to the winner - the notice reports that decision rather than asking you to make one - and running the command on the winning note itself stays silent, because nothing outranks it. Only **Collect attachments in current note** reports this; a folder-wide or vault-wide run visits notes you never singled out, so it would be a box per attachment.

### Try it

**Note priorities** belongs to **`Advanced Rename and Delete Handler`** since 12.0.0, so it is set in that plugin's settings tab. The set-up button creates `Note priorities demo/` with `shared.png` embedded by a note, `Note`, and by a drawing, `Drawing.excalidraw.md`. **Note priorities** starts empty and **Collect attachment used by multiple notes mode** is `Skip`. The drawing is a plain file with the drawing's extension, so `Excalidraw` does not need to be installed.

```code-button
---
caption: Set up the note-priorities demo
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'priorities');
```

Collect `Note` with the list empty. The image is left alone: two notes reference it, nothing ranks them, and the mode says skip.

```code-button
---
caption: Collect Note with no priorities
---
await require('/demoSetup.ts').collectInDemo(app, 'priorities');
```

Set **Note priorities** to `.md` then `.excalidraw.md`, and collect the *drawing*. The image moves into the markdown note's attachment folder, `assets/Note/`, because `Note` outranks the drawing, and a notice names `Note`, with a link to open it, so you can see who really owns the image.

```code-button
---
caption: Rank .md above .excalidraw.md and collect the drawing
---
const demoSetup = require('/demoSetup.ts');
await demoSetup.changeNotePriorities(app, ['.md', '.excalidraw.md']);
await demoSetup.collectInDemo(app, 'priorities', ['Drawing.excalidraw.md']);
```

Collect `Note` itself. The image is already in its folder, so nothing moves and nothing is reported.

```code-button
---
caption: Collect Note now that it owns the image
---
await require('/demoSetup.ts').collectInDemo(app, 'priorities');
```

Embed the image in a *second* markdown note, set the mode to `Prompt` so the plugin asks instead of skipping, and collect `Note` again. The two markdown notes now tie, so the dialog appears and names those two. The drawing, which the list ranked below them, is not on it. The dialog is left open for you to answer.

```code-button
---
caption: Add a second markdown note and collect into a tie
---
await require('/demoSetup.ts').collectPrioritiesTie(app);
```

Manual equivalent: embed one image in a note and in an `.excalidraw.md` file, edit **Note priorities** in **Settings -> Community plugins -> `Advanced Rename and Delete Handler`**, set **Collect attachment used by multiple notes mode** in **Settings -> Community plugins -> `Custom Attachment Location`**, and run **Collect attachments in current note** in each note.

## When a whole file type is shared on purpose

Some file types are shared between notes by design, and for those the question above is not worth asking at all. List their extensions under **Exclude extensions from multiple notes check** (`excludeExtensionsFromMultipleNotesCheck`) and the check never runs for them: they are collected like any singly-referenced attachment, with Obsidian rewriting every note that points at them.

- One extension per line, with or without the leading dot - `af` and `.af` are the same entry.
- Matching ignores case, so one line covers `.af`, `.AF` and `.Af`.
- A compound extension works too: `excalidraw.md` matches `Drawing.excalidraw.md` and nothing else.

This is the mirror image of `excludePathsFromMultipleNotesCheck`. That one names the **notes** that do not count as a second referrer; this one names the **attachments** that are expected to have several. It is read by **Collect attachments** and **Move attachment to proper folder**. **Delete unused attachments deliberately ignores it** - there the same list would mean "stop counting the notes that still reference this file", which would trash exactly the shared files the setting exists to protect. See [08 Delete unused attachments](<./08 Delete unused attachments.md>).

### Try it

The set-up button creates `Shared type demo/` with two files, `shared.af` and `shared.png`, each linked from two ordinary notes, `Note A` and `Note B`. The mode is **Skip** and the extension list starts empty.

```code-button
---
caption: Set up the shared-type demo with no extension listed
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'extensions');
```

Collect `Note A`. Nothing moves: both files are referenced by two notes, and the mode says skip.

```code-button
---
caption: Collect Note A with no extension listed
---
await require('/demoSetup.ts').collectInDemo(app, 'extensions');
```

Start over with `af` listed under **Exclude extensions from multiple notes check** and collect again. `shared.af` moves into `assets/Note A/`, and the link in `Note B` follows it. `shared.png` is skipped again, so the list exempts the types you named rather than switching the check off.

```code-button
---
caption: Start over with af listed
---
await require('/demoSetup.ts').setUpCollectDemo(app, 'extensions', { excludeExtensionsFromMultipleNotesCheck: ['af'] });
```

```code-button
---
caption: Collect Note A with af listed
---
await require('/demoSetup.ts').collectInDemo(app, 'extensions');
```

Manual equivalent: link two files from two notes, run **Collect attachments in current note** with **Collect attachment used by multiple notes mode** set to `Skip`, then add the extension to **Exclude extensions from multiple notes check** in **Settings -> Community plugins -> `Custom Attachment Location`** and repeat with fresh copies.

## Put the settings back

The demos on this page change settings that apply to the whole vault: the location for new attachments, the collect destination, and every switch above, plus **Note priorities** in **`Advanced Rename and Delete Handler`**. This button puts all of them back to the values this vault ships with.

```code-button
---
caption: Restore the collect settings
---
await require('/demoSetup.ts').restoreCollectSettings(app);
```

Manual equivalent: set each setting named on this page back by hand - all of them empty or off, the mode `Skip`, the location `./assets/{{noteFileName}}`.
