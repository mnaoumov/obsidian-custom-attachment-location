# `{{date}}`

Current date/time.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  momentJsFormat: string;
}
```

## Default (omitted) format

`null`, invalid.

## Examples

- `{{date:{momentJsFormat:'YYYY-MM-DD'}}}`: `2025-12-31`.
- `{{date:YYYY-MM-DD}}`: `2025-12-31`, the scalar shorthand for the example above.
- `{{date:{momentJsFormat:'YYYY-MM-DD [at] HH-mm'}}}`: `2025-12-31 at 18-15` (literal text escaped with `[...]`; see [Escaping literal text inside a Moment.js format](<../09 Token reference.md#escaping-literal-text-inside-a-momentjs-format>)).
