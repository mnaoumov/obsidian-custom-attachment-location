# `{{originalAttachmentFileCreationDate}}`

Creation date/time of the attachment file. The file's own date, which a rename does not change, so it reads the same as [`{{attachmentFileCreationDate}}`](<./attachmentFileCreationDate.md>); the name is kept for the templates that already use it.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  momentJsFormat: string;
  valueWhenUnknown?: 'empty' | 'now'; // default: 'empty'
}
```

`momentJsFormat` uses [Moment.js format].

## Default (omitted) format

`null`, invalid.

## Examples

- `{{originalAttachmentFileCreationDate:{momentJsFormat:'YYYY-MM-DD'}}}`: `2025-12-31`.
- `{{originalAttachmentFileCreationDate:{momentJsFormat:'YYYY-MM-DD',valueWhenUnknown:'empty'}}}`: `(empty)`.

[Moment.js format]: https://momentjs.com/docs/#/displaying/format/
