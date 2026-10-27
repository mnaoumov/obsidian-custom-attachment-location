# Link display text

By default, a link Obsidian inserts to an attachment shows the file path (or, for an embed, nothing readable). With **`shouldSetLinkDisplayTextToAttachmentFileName`** turned on, every link the plugin generates to an **attachment** uses the attachment's base name (the file name without its extension) as the visible display text - so `report-2026.pdf` shows up as `report-2026` instead of a long path.

Notes are deliberately left alone: a link from one note to another keeps Obsidian's normal display text. And if you provide an explicit alias, or the image has a cached size, that wins over the base-name default.

## Try it

1. Open **Settings -> Community plugins -> `Custom Attachment Location`** and turn on **Set link display text to attachment file name**.
2. Open a note and drag a non-image attachment, for example a PDF, into it.
3. Look at the inserted link: it now reads `[[.../report-2026.pdf|report-2026]]`, showing `report-2026` as the display text.
4. Insert a link to another **note** and confirm its display text is unchanged - the setting only affects attachments.

The first button does step 1:

```code-button
---
caption: Turn on Set link display text to attachment file name
---
await require('/demoSetup.ts').changeSettings(app, { shouldSetLinkDisplayTextToAttachmentFileName: true });
```

The second does steps 2 to 4. It creates `Materials/07 Link display text/` with `report-2026.pdf`, a note, `Other note`, and a note, `Link display demo`, into which it writes the link Obsidian generates to each - the same call a drop and a link suggestion make. It opens that note and names both links in a notice. Press it with the setting off, then on, to see the difference:

```code-button
---
caption: Insert a PDF link and a note link
---
await require('/demoSetup.ts').insertLinksForDisplayTextDemo(app);
```

```code-button
---
caption: Turn the setting off again
---
await require('/demoSetup.ts').changeSettings(app, { shouldSetLinkDisplayTextToAttachmentFileName: false });
```

Manual equivalent: the four steps above.

## Keep the original name after renaming

Set **Inserted link text** (`insertedLinkText`) under **Advanced** to `{{originalAttachmentFileName}}`. A PDF arriving as `report-2026.pdf`, saved as `renamed-report.pdf`, is inserted as `[[.../renamed-report.pdf|report-2026]]`. With Obsidian's Markdown links enabled it becomes `[report-2026](.../renamed-report.pdf)`. Add `.{{originalAttachmentFileExtension}}` to include the extension in the text. The same tokens used by file-name patterns are available, including asynchronous custom tokens.

The template is empty by default. It applies when an attachment is imported, including a paste, a drop or a mobile share; it does not rewrite existing links. Images skip the template because an alias such as `300` or `1920x1080` would resize an embed. Explicit aliases and cached image sizes keep priority. Link delimiters (`|`, `[`, `]`, `#`, `^`, backslashes and angle brackets) use their full width equivalents in template text so they cannot change the link target; line breaks become spaces.

Drop a PDF into a note after enabling the setting to try it yourself. These buttons create an isolated sample PDF and insert the link through the same destination resolver and link generator that imports use. Each resets its sample folder and configures the patterns it needs.

```code-button
---
caption: Rename a PDF and show its original name
---
await require('/demoSetup.ts').insertOriginalNameLinkDemo(app, true);
```

```code-button
---
caption: Turn off the template and insert the same example
---
await require('/demoSetup.ts').insertOriginalNameLinkDemo(app, false);
```

Relevant settings: `insertedLinkText`, `shouldSetLinkDisplayTextToAttachmentFileName` (see [06 Settings](<./06 Settings.md>)).
