[Docs](https://github.com/mnaoumov/obsidian-custom-attachment-location/)

# Collect attachments

Changing your location or naming pattern only affects *new* attachments. To bring **existing** attachments into line with the current settings, the plugin adds **Collect attachments** commands. They move each attachment referenced by a note into the folder (and under the name) your patterns would produce today.

## Commands

Open the Command Palette (`Ctrl`/`Cmd` + `P`) and search for *Custom Attachment Location*:

- **Collect attachments in current note** - reorganizes only the attachments used by the active note.
- **Collect attachments in current folder** - every note in the active note's folder.
- **Collect attachments in entire vault** - the whole vault at once.

There is also **Move attachment to proper folder**, which relocates a single attachment file to where the settings say it belongs.

## Try it

1. Paste a couple of images into [[01 Attachment folder location]] and [[02 Attachment file naming]] (you supply the files).
2. Change **Location for new attachments** in the settings to something new.
3. Run **Collect attachments in entire vault** and watch the existing attachments move to match the new pattern.

Relevant settings: `shouldRenameCollectedAttachments`, `collectedAttachmentFileName`, `collectAttachmentUsedByMultipleNotesMode`, and `moveAttachmentToProperFolderUsedByMultipleNotesMode` control how collecting handles renaming and attachments shared by several notes. All keys are explained in [[06 Settings]].
