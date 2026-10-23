# `{{generatedAttachmentFileName}}`

The generated file name of the attachment (available only inside [`markdownUrlFormat`](<../06 Settings.md>) setting).

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
  }
}
```

## Default (omitted) format

`null`, equivalent to `{}`.

## Examples

- `{{generatedAttachmentFileName}}`: `alpha/bravo/charlie.pdf -> charlie`.
- `{{generatedAttachmentFileName:{case:'lower'}}}`: `alpha/bravo/CHARLIE.pdf -> charlie`.
- `{{generatedAttachmentFileName:{case:'upper'}}}`: `alpha/bravo/charlie.pdf -> CHARLIE`.
- `{{generatedAttachmentFileName:{slugify:true}}}`: `alpha/bravo/charlie delta.pdf -> charlie-delta`.
- `{{generatedAttachmentFileName:{trim:{side:'left',length:2}}}}`: `alpha/bravo/charlie.pdf -> ch`.
- `{{generatedAttachmentFileName:{trim:{side:'right',length:2}}}}`: `alpha/bravo/charlie.pdf -> ie`.
