# `{{attachmentFileCreationDate}}`

Creation date/time of the attachment file. The same value as [`{{originalAttachmentFileCreationDate}}`](<./originalAttachmentFileCreationDate.md>).

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

- `{{attachmentFileCreationDate:YYYY-MM-DD}}`: `2025-12-31`.
- `{{attachmentFileCreationDate:{momentJsFormat:'YYYY-MM-DD',valueWhenUnknown:'now'}}}`: today's date when the file has no creation date yet.

[Moment.js format]: https://momentjs.com/docs/#/displaying/format/
