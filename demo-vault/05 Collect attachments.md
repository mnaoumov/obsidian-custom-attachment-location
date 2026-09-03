# Collect attachments

Changing your location or naming pattern only affects *new* attachments. To bring **existing** attachments into line with the current settings, the plugin adds **Collect attachments** commands. They move each attachment referenced by a note into the folder (and under the name) your patterns would produce today.

## Commands

Open the Command Palette (`Ctrl`/`Cmd` + `P`) and search for *Custom Attachment Location*:

- **Collect attachments in current note**
  - reorganizes only the attachments used by the active note.
- **Collect attachments in current folder**
  - every note in the active note's folder.
- **Collect attachments in entire vault**
  - the whole vault at once.

There is also **Move attachment to proper folder**, which relocates a single attachment file to where the settings say it belongs.

## Try it

1. Paste a couple of images into [01 Attachment folder location](<./01 Attachment folder location.md>) and [02 Attachment file naming](<./02 Attachment file naming.md>) (you supply the files).
2. Change **Location for new attachments** in the settings to something new.
3. Run **Collect attachments in entire vault** and watch the existing attachments move to match the new pattern.

Relevant settings: `shouldRenameCollectedAttachments`, `collectedAttachmentFileName`, `collectAttachmentUsedByMultipleNotesMode`, and `moveAttachmentToProperFolderUsedByMultipleNotesMode` control how collecting handles renaming and attachments shared by several notes; `excludePathsFromMultipleNotesCheck` lets you ignore certain notes (e.g. `.excalidraw` drawings) from that shared-attachment check. All keys are explained in [06 Settings](<./06 Settings.md>).

## Safety net for non-standard references

The plugin only sees attachment references that Obsidian indexes - traditional `[[wikilink]]` / `![](markdown)` embeds. If another plugin renders images through its own syntax (a raw `<img src="...">`, a custom code block, an image-slider list, etc.), those references are invisible to collecting, so an attachment used only that way could be moved to an unexpected place and later lost.

Turn on **Skip collecting attachments referenced by a raw path** (`shouldSkipCollectingAttachmentsReferencedByRawPath`) to guard against that: before moving an attachment, the plugin scans every note's raw text for the attachment's path or file name and, if it finds a non-indexed reference, leaves the attachment in place instead of collecting it.

### Try it

1. Create a note `raw-ref.md` whose body embeds an image with raw HTML, e.g. `<img src="my-image.png">` (Obsidian will not index this link).
2. Reference the same image with a normal `![[my-image.png]]` embed from another note and run **Collect attachments** with the setting **off** - the image is relocated even though `raw-ref.md` still points at the old path.
3. Turn the setting **on** and repeat - the image is left where it is, and a notice reports that it is referenced by a raw path.

## Attachments that are really a folder

Some attachments are a directory tree rather than a file: a page saved from a browser sits next to a `_files/` folder holding its images and stylesheets, and a drawing sits next to the pictures it references. Collecting moves the file that was linked and leaves its siblings behind, so the attachment arrives intact-looking but blank.

List those folders under **Attachment unit folders** (`attachmentUnitFolderPaths`) and the whole folder travels whenever collecting moves any attachment inside it. The folder lands in the note's attachment folder under its own name, so its internal shape - and the relative links inside it - keep working.

Entries use the same vocabulary as the include / exclude path settings: a plain entry is a path from the vault root, while an entry wrapped in `/` is a regular expression. To designate a folder by *name* wherever it appears, use the regular-expression form, e.g. `/(^|\/)[^/]+_files(\/|$)/`.

Two things worth knowing:

- When folders are nested and both are designated, the **outermost** one travels. Moving the inner one would tear the outer tree in half, which is the failure this setting exists to prevent.
- An attachment inside such a folder that is referenced by several notes is left where it is rather than copied, because copying the single file out of the folder produces exactly the broken attachment the setting prevents.

### Try it

1. Create `saved-page/page_files/logo.png` and `saved-page/page_files/style.css`, and a note embedding only `![[saved-page/page_files/logo.png]]`.
2. Run **Collect attachments in current note** with the setting empty - only `logo.png` moves, and `style.css` is stranded.
3. Add `saved-page/page_files` to **Attachment unit folders** and repeat with a fresh copy - the whole `page_files` folder moves, `style.css` included.

## When several notes reference the same attachment

An attachment referenced by more than one note has no single correct home, so collecting falls back to **Collect attachment used by multiple notes mode** - skip it, copy it, cancel, or ask.

**Note priorities** (`notePriorities`) lets you answer the question once instead. List the kinds of note in order, highest priority first, and the winning note takes the attachment:

- an entry starting with a dot is a file extension, e.g. `.md`;
- an entry starting with `property:` matches a frontmatter property, optionally with a value, e.g. `property:excalidraw-plugin` or `property:type=drawing`;
- anything else is a path from the vault root, or a `/regular expression/`.

When a note matches several entries, the **longest** one decides its rank. That is what makes the common case work: `drawing.excalidraw.md` also ends with `.md`, so without it a list of `.md` then `.excalidraw.md` would tie instead of putting the plain note first.

Three things worth knowing:

- If no entry matches, or if the best entry matches several of the referencing notes, nothing is decided here and the mode setting handles it as before. A tie is never broken silently. **The dialog that then appears says which of the three it was** - the list is empty, nothing matched, or several notes matched equally - so you can tell a list you never configured from one that simply did not apply.
- **The dialog lists only the notes sharing the best rank.** A note the list deliberately ranked lower cannot break the tie between the ones above it, so it is left out rather than offered as if it could. When the list decides nothing at all - it is empty, or it matches none of them - every referencing note is listed, because nothing has ruled any of them out. The console message names exactly the same notes as the dialog.
- The winner does not have to be the note you ran the command on. Collecting from a drawing can hand the image to a markdown note that outranks it. That is the point of the setting, and why it is empty by default.
- Once a single note wins, the collect is settled, so it stays quiet. If the winner **already** holds the attachment there is simply nothing to move, and no shared-attachment dialog or notice appears - exactly as for an attachment only one note references.

### Try it

1. Embed the same image in a note and in an Excalidraw drawing.
2. Run **Collect attachments in current note** with **Note priorities** empty - the image is left alone (or handled per the mode).
3. Set **Note priorities** to `.md` then `.excalidraw.md` and repeat - the image moves into the markdown note's attachment folder, whichever of the two you ran the command on.
4. Run it a second time on the markdown note - the image is already in its folder, so nothing moves and nothing is reported.
5. Embed the same image in a *second* markdown note and run it again - the two markdown notes now tie, so the dialog appears and names those two. The drawing, which the list ranked below them, is not on it.
