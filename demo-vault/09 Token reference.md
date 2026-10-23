# Token reference

Every token, each with its own note in the `Tokens` folder giving its format schema and worked examples. This is the catalog you scan when you already know you want a token and need its exact spelling or options; for what a pattern *is* and the handful of tokens most people use, start at [03 Tokens and patterns](<./03 Tokens and patterns.md>).

Tokens work in the three pattern settings: `attachmentFolderPath`, `generatedAttachmentFileName` and `markdownUrlFormat` - see [06 Settings](<./06 Settings.md>). To define your own, see [04 Custom tokens](<./04 Custom tokens.md>).

Token strings:

- `{{token}}`: Use token default format (`null`).
- `{{token:{...}}}`: Use explicit format parsed as a **JSON5 object** (single-line).
- `{{token:text}}`: The scalar shorthand, text free of `{` and `}`. The seven date tokens take it as their Moment.js format, so `{{date:YYYY-MM-DD}}` means `{{date:{momentJsFormat:'YYYY-MM-DD'}}}` - the same form core's Templates plugin uses. A custom token receives the text itself as `ctx.format`; every other built-in token rejects it.

`token` is case-insensitive. Format object keys and values are case-sensitive.

## Tokens

### The attachment as it is now

| Token | What it gives |
| --- | --- |
| [`{{attachmentFileName}}`](<./Tokens/attachmentFileName.md>) | The attachment's current file name, without its extension. |
| [`{{attachmentFileExtension}}`](<./Tokens/attachmentFileExtension.md>) | The attachment's current extension, without its dot. |
| [`{{attachmentFileHash}}`](<./Tokens/attachmentFileHash.md>) | A hash of the attachment's content, so the same bytes always get the same name. |
| [`{{attachmentFileSize}}`](<./Tokens/attachmentFileSize.md>) | The attachment's size, in bytes, KB or MB. |
| [`{{attachmentFileCreationDate}}`](<./Tokens/attachmentFileCreationDate.md>) | When the attachment file was created. |
| [`{{attachmentFileModificationDate}}`](<./Tokens/attachmentFileModificationDate.md>) | When the attachment file was last modified. |

### The attachment as it arrived

| Token | What it gives |
| --- | --- |
| [`{{originalAttachmentFileName}}`](<./Tokens/originalAttachmentFileName.md>) | The file name the attachment arrived with, kept through renames and moves. |
| [`{{originalAttachmentFileExtension}}`](<./Tokens/originalAttachmentFileExtension.md>) | The extension of the name the attachment arrived with. |
| [`{{originalAttachmentFileCreationDate}}`](<./Tokens/originalAttachmentFileCreationDate.md>) | The same value as `{{attachmentFileCreationDate}}`, kept for existing templates. |
| [`{{originalAttachmentFileModificationDate}}`](<./Tokens/originalAttachmentFileModificationDate.md>) | The same value as `{{attachmentFileModificationDate}}`, kept for existing templates. |

### The note

| Token | What it gives |
| --- | --- |
| [`{{noteFileName}}`](<./Tokens/noteFileName.md>) | The note's file name, without its extension. |
| [`{{noteFilePath}}`](<./Tokens/noteFilePath.md>) | The note's full path. |
| [`{{noteFolderName}}`](<./Tokens/noteFolderName.md>) | The name of the note's folder, or of any folder above it. |
| [`{{noteFolderPath}}`](<./Tokens/noteFolderPath.md>) | The full path of the note's folder. |
| [`{{noteFileCreationDate}}`](<./Tokens/noteFileCreationDate.md>) | When the note file was created. |
| [`{{noteFileModificationDate}}`](<./Tokens/noteFileModificationDate.md>) | When the note file was last modified. |
| [`{{frontmatter}}`](<./Tokens/frontmatter.md>) | A value from the note's frontmatter, nested keys included. |
| [`{{heading}}`](<./Tokens/heading.md>) | The heading above the cursor where the attachment is inserted. |
| [`{{sequenceNumber}}`](<./Tokens/sequenceNumber.md>) | The position of the note's first link to the attachment, during a note rename or a collect. |

### The generated attachment, in `markdownUrlFormat` only

| Token | What it gives |
| --- | --- |
| [`{{generatedAttachmentFileName}}`](<./Tokens/generatedAttachmentFileName.md>) | The file name the plugin generated for the attachment. |
| [`{{generatedAttachmentFilePath}}`](<./Tokens/generatedAttachmentFilePath.md>) | The file path the plugin generated for the attachment. |

### Values made at the time

| Token | What it gives |
| --- | --- |
| [`{{date}}`](<./Tokens/date.md>) | The current date and time. |
| [`{{prompt}}`](<./Tokens/prompt.md>) | A value you type into a dialog when the attachment is saved. |
| [`{{random}}`](<./Tokens/random.md>) | Random letters and digits. |
| [`{{uuid}}`](<./Tokens/uuid.md>) | A random UUID. |

## Format (JSON5)

The `<format>` part must be a JSON5 **object** (single line), i.e. it must start with `{` and end with `}`.

- Property names can be quoted or unquoted: `{{attachmentFileSize:{unit:'KB','decimalPoints':2}}}`.
- Strings must be quoted: `{{date:{momentJsFormat:'YYYYMMDD'}}}`.
- JSON5 allows (optional) trailing commas: `{{attachmentFileSize:{unit:'KB',decimalPoints:2,}}}`.

If you need quotes inside a JSON5 string, either escape them or switch quote types:

- `{{date:{momentJsFormat:'It\'s {{date}}'}}}`
- `{{date:{momentJsFormat:"It's {{date}}"}}}`

### Escaping literal text inside a Moment.js format

The `momentJsFormat` value is a [Moment.js format string](https://momentjs.com/docs/#/displaying/format/). Letters that are Moment.js format tokens (such as `a`, `A`, `h`, `H`, `D`, `M`, `Y`) are **always** interpreted as tokens, even inside JSON5 quotes. Wrapping literal text in quotes does **not** escape it - e.g. `'YYYY-MM-DD 'at' HH:mm'` outputs `2026-04-02 pmt 18-15` because Moment.js reads `a` as the am/pm marker and `t` as a literal.

To include literal text, escape it with **square brackets** `[...]` (the Moment.js escape syntax), not quotes:

- `{{date:{momentJsFormat:'YYYY-MM-DD [at] HH:mm'}}}` → `2026-04-02 at 18:15`
- `{{date:{momentJsFormat:'[Backup] YYYY [taken at] HH[h]mm'}}}` → `Backup 2026 taken at 18h15`

## Validation (strict)

Each token validates its own `format` shape at runtime. Unknown object properties are rejected (strict validation).

Example (error):

`❌ {{attachmentFileSize:{unit:'B',decimalPoints:3,unknownProperty:'alpha'}}}`

## Two families: the attachment as it is now, and as it arrived

`{{attachmentFileName}}` and `{{attachmentFileExtension}}` read the attachment **as it is right now**: the incoming file's name while you paste or drop it, the file's current name when a collect or a note rename moves it.

`{{originalAttachmentFileName}}` and `{{originalAttachmentFileExtension}}` read the name the attachment **arrived with**. The plugin remembers it when it saves a pasted, dropped, shared or downloaded attachment, and keeps it through every rename and move Obsidian reports, its own and yours. So a collect template such as `{{noteFileName}}-{{originalAttachmentFileName}}` gives `Note-img` on the first collect and still `Note-img` on the next one, instead of `Note-Note-img`.

When the original name is not known - the file predates the record, was renamed outside Obsidian, or was synced from another device with no record - the current name is used, it is remembered as the original from then on, and one notice per operation says so. Its **Details** button lists the attachments. Turn the notice off with `shouldWarnWhenOriginalAttachmentNameIsUnknown`. The commands **Show original attachment names**, **Prune original attachment names** and **Remember current name as original** let you look at the remembered names and correct them; see [05 Collect attachments](<./05 Collect attachments.md#original-attachment-names>).

The dates are the file's own, which a rename does not change, so `{{attachmentFileCreationDate}}` and `{{originalAttachmentFileCreationDate}}` read the same value, and so do the two modification-date tokens.
