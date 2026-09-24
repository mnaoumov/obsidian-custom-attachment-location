# Tokens and patterns

A *pattern* is just text with **tokens** in it. Tokens are written `{{token}}` (default format) or `{{token:{...}}}` (with an explicit [JSON5](https://json5.org/) format object) - the `{{...}}` language Obsidian's own Templates plugin uses. The date tokens also take core's short form, `{{date:YYYY-MM-DD}}`. Token names are case-insensitive; format keys are case-sensitive. Patterns power three settings: `attachmentFolderPath`, `generatedAttachmentFileName`, and `markdownUrlFormat`.

Example folder pattern:

```text
./assets/{{noteFileName}}/{{date:{momentJsFormat:'YYYY'}}}
```

## Commonly used tokens

- `{{noteFileName}}`
  - the current note's file name (basename).
- `{{noteFilePath}}`
  - the current note's full path.
- `{{noteFolderName}}` / `{{noteFolderPath}}`
  - the note's folder name / full folder path.
- `{{originalAttachmentFileName}}`
  - the pasted/dragged file's original name.
- `{{originalAttachmentFileExtension}}`
  - its extension.
- `{{date:{momentJsFormat:'YYYY-MM-DD'}}}`
  - current date/time in [Moment.js](https://momentjs.com/docs/#/displaying/format/) format.
- `{{uuid}}` / `{{random:{length:6}}}`
  - a random UUID / random string, for guaranteed-unique names.
- `{{prompt}}`
  - ask you for a value each time (with a file preview).
- `{{frontmatter:{key:'project'}}}`
  - a value read from the note's frontmatter.
- `{{heading}}`
  - the nearest heading above the cursor.
- `{{sequenceNumber}}`
  - the position of the first link to the attachment (used during renames and collecting).

## Format objects

The part after the colon is a single-line JSON5 object. Strings must be quoted; property names may be quoted or not; trailing commas are allowed:

```text
{{noteFileName:{case:'lower',slugify:true}}}
{{attachmentFileSize:{unit:'KB',decimalPoints:2}}}
```

Unknown format properties are rejected with an error, so a typo fails loudly instead of silently.

The full catalog — every token, its format schema and worked examples — is [09 Token reference](<./09 Token reference.md>). To define your own tokens, see [04 Custom tokens](<./04 Custom tokens.md>).

## Upgrading from `${...}`

Before 14.0.0 tokens were written `${token}` and `${token:{...}}`. That syntax no longer works. Your saved patterns are rewritten to `{{...}}` automatically the first time 14.0.0 loads. Your custom tokens code is JavaScript you wrote, so it is left as it is: a `ctx.fillTemplate('${noteFileName}')` in it fails with an error naming the `{{noteFileName}}` that replaces it, rather than silently producing a wrong name.
