# `{{noteFileModificationDate}}`

Note file modification date/time.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  momentJsFormat: string;
}
```

`momentJsFormat` uses [Moment.js format].

## Default (omitted) format

`null`, invalid.

## Examples

- `{{noteFileModificationDate:{momentJsFormat:'YYYY-MM-DD'}}}`: `2025-12-31`.

[Moment.js format]: https://momentjs.com/docs/#/displaying/format/
