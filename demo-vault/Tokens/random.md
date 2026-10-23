# `{{random}}`

Random value.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  digits?: boolean; // default: true
  length?: number; // default: 1
  letterCase?: 'lower' | 'mixed' | 'upper'; // default: 'upper'
  letters?: boolean; // default: true
}
```

## Default (omitted) format

`null`, equivalent to `{}`.

## Examples

- `{{random}}`: `7`.
- `{{random:{digits:false}}}`: `M`.
- `{{random:{length:10}}}`: `8JR91VMU9R`.
- `{{random:{letterCase:mixed,length:10}}}`: `8Jr91vmU9R`.
- `{{random:{letters:false}}}`: `7`.
