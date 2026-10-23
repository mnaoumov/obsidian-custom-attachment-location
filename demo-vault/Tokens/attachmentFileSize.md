# `{{attachmentFileSize}}`

Size of the attachment file.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  decimalPoints?: number; // default: 0
  unit?: 'B' | 'KB' | 'MB'; // default: 'B'
}
```

## Default (omitted) format

`null`, equivalent to `{}`.

## Examples

- `{{attachmentFileSize}}`: `123`.
- `{{attachmentFileSize:{unit:'KB',decimalPoints:2}}}`: `456.78`.
