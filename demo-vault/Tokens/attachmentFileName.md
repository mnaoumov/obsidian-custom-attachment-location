# `{{attachmentFileName}}`

File name of the attachment as it is now, without its extension: the incoming file's while pasting, the current one when a collect or a note rename moves it. Use it where you mean the current name; [`{{originalAttachmentFileName}}`](<./originalAttachmentFileName.md>) is the name it arrived with.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  case?: 'lower' | 'title' | 'upper';
  collapseWhitespace?: boolean; // default: false
  slugify?: boolean; // default: false
  trim?: {
    length: number;
    side: 'left' | 'right';
  };
}
```

## Default (omitted) format

`null`, equivalent to `{}`.

## Examples

- `{{attachmentFileName}}`: `Note-img.png -> Note-img`.
- `{{attachmentFileName:{case:'lower'}}}`: `Note-IMG.png -> note-img`.
