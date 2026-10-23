# `{{noteFileName}}`

Current note file name.

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

- `{{noteFileName}}`: `alpha/bravo/charlie.md -> charlie`.
- `{{noteFileName:{case:'lower'}}}`: `alpha/bravo/CHARLIE.md -> charlie`.
- `{{noteFileName:{case:'upper'}}}`: `alpha/bravo/charlie.md -> CHARLIE`.
- `{{noteFileName:{slugify:true}}}`: `alpha/bravo/charlie delta.md -> charlie-delta`.
- `{{noteFileName:{trim:{side:'left',length:2}}}}`: `alpha/bravo/charlie.md -> ch`.
- `{{noteFileName:{trim:{side:'right',length:2}}}}`: `alpha/bravo/charlie.md -> ie`.
