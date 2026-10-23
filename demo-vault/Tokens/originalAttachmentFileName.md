# `{{originalAttachmentFileName}}`

File name the attachment arrived with, without its extension: the name it had when it was pasted, dropped, shared or downloaded, kept through every rename and move Obsidian reports. When that name is not known, the current name is used, with a warning; see [Two families](<../09 Token reference.md#two-families-the-attachment-as-it-is-now-and-as-it-arrived>). [`{{attachmentFileName}}`](<./attachmentFileName.md>) is the current name.

Up to 16.0.0 this token read the current name, so a template that prepends to it stacked on every collect. Existing templates keep working and get the new meaning. A template that really wants the current name uses [`{{attachmentFileName}}`](<./attachmentFileName.md>).

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

- `{{originalAttachmentFileName}}`: `alpha.pdf -> alpha`.
- `{{originalAttachmentFileName:{case:'lower'}}}`: `ALPHA.pdf -> alpha`.
- `{{originalAttachmentFileName:{case:'upper'}}}`: `alpha.pdf -> ALPHA`.
- `{{originalAttachmentFileName:{slugify:true}}}`: `alpha bravo.pdf -> alpha-bravo`.
- `{{originalAttachmentFileName:{trim:{side:'left',length:2}}}}`: `alpha.pdf -> al`.
- `{{originalAttachmentFileName:{trim:{side:'right',length:2}}}}`: `alpha.pdf -> ha`.
