# `{{noteFolderName}}`

Current note's folder name.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  case?: 'lower' | 'title' | 'upper';
  collapseWhitespace?: boolean; // default: false
  pick?: {
    from: 'start' | 'end';
    index?: number; // default: 0
  };
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

- `{{noteFolderName}}`: `alpha/bravo/charlie/delta.md -> charlie`.
- `{{noteFolderName:{pick:{from:'end',index:1}}}}`: `alpha/bravo/charlie/delta/echo/foxtrot.md -> delta`.
- `{{noteFolderName:{pick:{from:'start',index:1}}}}`: `alpha/bravo/charlie/delta/echo/foxtrot.md -> bravo`.
- `{{noteFolderName:{case:'lower'}}}`: `alpha/bravo/CHARLIE/delta.md -> charlie`.
- `{{noteFolderName:{case:'upper'}}}`: `alpha/bravo/charlie/delta.md -> CHARLIE`.
- `{{noteFolderName:{slugify:true}}}`: `alpha/bravo/charlie delta/echo.md -> charlie-delta`.
- `{{noteFolderName:{trim:{side:'left',length:2}}}}`: `alpha/bravo/charlie/delta.md -> ch`.
- `{{noteFolderName:{trim:{side:'right',length:2}}}}`: `alpha/bravo/charlie/delta.md -> ie`.
