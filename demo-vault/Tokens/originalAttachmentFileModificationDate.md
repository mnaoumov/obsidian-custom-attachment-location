# `{{originalAttachmentFileModificationDate}}`

Modification date/time of the attachment file. The file's own date, so it reads the same as [`{{attachmentFileModificationDate}}`](<./attachmentFileModificationDate.md>); the name is kept for the templates that already use it.

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

- `{{originalAttachmentFileModificationDate:{momentJsFormat:'YYYY-MM-DD'}}}`: `2025-12-31`.
- `{{originalAttachmentFileModificationDate:{momentJsFormat:'YYYY-MM-DD',valueWhenUnknown:'empty'}}}`: `(empty)`.

[Moment.js format]: https://momentjs.com/docs/#/displaying/format/
