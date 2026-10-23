# `{{frontmatter}}`

Frontmatter value of the current note.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  key: string;
}
```

Nested keys are supported, e.g. `'key1.key2.3.key4'`.

## Default (omitted) format

`null`, invalid.

## Examples

- `{{frontmatter:{key:'tags.0'}}}`: `tag1`.
