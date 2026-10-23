# `{{sequenceNumber}}`

Sequential number of the first link within the note to the attachment file. Applicable only during note rename and collecting attachments.

When the link cannot be found, the value of the token is `0`.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  length?: number; // default: 1
}
```

## Default (omitted) format

`null`, equivalent to `{}`.

## Examples

- `{{sequenceNumber}}`: `1`.
- `{{sequenceNumber:{length:4}}}`: `0001`.
