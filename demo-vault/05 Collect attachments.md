# Collect attachments

Changing your location or naming pattern only affects *new* attachments. To bring **existing** attachments into line with the current settings, the plugin adds **Collect attachments** commands. They move each attachment referenced by a note into the folder (and under the name) your patterns would produce today.

## Commands

Open the Command Palette (`Ctrl`/`Cmd` + `P`) and search for *Custom Attachment Location*:

- **Collect attachments in current note** - reorganizes only the attachments used by the active note.
- **Collect attachments in current folder** - every note in the active note's folder.
- **Collect attachments in entire vault** - the whole vault at once.

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
