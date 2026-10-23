# `{{uuid}}`

Random UUID value.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  case?: 'lower' | 'upper'; // default: 'lower'
  hyphens?: boolean; // default: true
}
```

## Default (omitted) format

`null`, equivalent to `{}`.

## Examples

- `{{uuid}}`: `edd5b990-fede-4e02-aa0e-1e9251da2f83`.
- `{{uuid:{case:'upper'}}}`: `EDD5B990-FEDE-4E02-AA0E-1E9251DA2F83`.
- `{{uuid:{hyphens:false}}}`: `edd5b990fede4e02aa0e1e9251da2f83`.
