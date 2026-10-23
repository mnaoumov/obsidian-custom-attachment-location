# `{{heading}}`

The heading above the cursor in the note editor where the attachment is inserted. Empty if such heading does not exist.

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  level?: '1' | '2' | '3' | '4' | '5' | '6' | 'any'; // default: 'any'
}
```

## Default (omitted) format

`null`, equivalent to `{}`.

## Examples

- `{{heading}}`: `Nearest heading at any level`.
- `{{heading:{level:'1'}}}`: `Nearest heading at level 1`.
- `{{heading:{level:'2'}}}`: `Nearest heading at level 2`.
- `{{heading:{level:'3'}}}`: `Nearest heading at level 3`.
- `{{heading:{level:'4'}}}`: `Nearest heading at level 4`.
- `{{heading:{level:'5'}}}`: `Nearest heading at level 5`.
- `{{heading:{level:'6'}}}`: `Nearest heading at level 6`.
