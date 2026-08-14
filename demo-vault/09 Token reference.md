# Token reference

Every token, its format schema and worked examples. This is the catalog you scan when you already
know you want a token and need its exact spelling or options; for what a pattern *is* and the
handful of tokens most people use, start at [03 Tokens and patterns](<./03 Tokens and patterns.md>).

Tokens work in the three pattern settings: `attachmentFolderPath`, `generatedAttachmentFileName`
and `markdownUrlFormat` — see [06 Settings](<./06 Settings.md>). To define your own, see
[04 Custom tokens](<./04 Custom tokens.md>).

Token strings:

- `${token}`: Use token default format (`null`).
- `${token:{...}}`: Use explicit format parsed as a **JSON5 object** (single-line).

`token` is case-insensitive. Format object keys and values are case-sensitive.

## Format (JSON5)

The `<format>` part must be a JSON5 **object** (single line), i.e. it must start with `{` and end with `}`.

- Property names can be quoted or unquoted: `${attachmentFileSize:{unit:'KB','decimalPoints':2}}`.
- Strings must be quoted: `${date:{momentJsFormat:'YYYYMMDD'}}`.
- JSON5 allows (optional) trailing commas: `${attachmentFileSize:{unit:'KB',decimalPoints:2,}}`.

If you need quotes inside a JSON5 string, either escape them or switch quote types:

- `${date:{momentJsFormat:'It\'s ${date}'}}`
- `${date:{momentJsFormat:"It's ${date}"}}`

### Escaping literal text inside a Moment.js format

The `momentJsFormat` value is a [Moment.js format string](https://momentjs.com/docs/#/displaying/format/). Letters that are Moment.js format tokens (such as `a`, `A`, `h`, `H`, `D`, `M`, `Y`) are **always** interpreted as tokens, even inside JSON5 quotes. Wrapping literal text in quotes does **not** escape it — e.g. `'YYYY-MM-DD 'at' HH:mm'` outputs `2026-04-02 pmt 18-15` because Moment.js reads `a` as the am/pm marker and `t` as a literal.

To include literal text, escape it with **square brackets** `[...]` (the Moment.js escape syntax), not quotes:

- `${date:{momentJsFormat:'YYYY-MM-DD [at] HH:mm'}}` → `2026-04-02 at 18:15`
- `${date:{momentJsFormat:'[Backup] YYYY [taken at] HH[h]mm'}}` → `Backup 2026 taken at 18h15`

## Validation (strict)

Each token validates its own `format` shape at runtime. Unknown object properties are rejected (strict validation).

Example (error):

`❌ ${attachmentFileSize:{unit:'B',decimalPoints:3,unknownProperty:'alpha'}}`

## `${attachmentFileSize}`

Size of the attachment file.

### Format schema

```ts
{
  decimalPoints?: number; // default: 0
  unit?: 'B' | 'KB' | 'MB'; // default: 'B'
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${attachmentFileSize}`: `123`.
- `${attachmentFileSize:{unit:'KB',decimalPoints:2}}`: `456.78`.

## `${date}`

Current date/time.

### Format schema

```ts
{
  momentJsFormat: string;
}
```

### Default (omitted) format

`null`, invalid.

### Examples

- `${date:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.
- `${date:{momentJsFormat:'YYYY-MM-DD [at] HH-mm'}}`: `2025-12-31 at 18-15` (literal text escaped with `[...]`; see [Escaping literal text inside a Moment.js format](#escaping-literal-text-inside-a-momentjs-format)).

## `${frontmatter}`

Frontmatter value of the current note.

### Format schema

```ts
{
  key: string;
}
```

Nested keys are supported, e.g. `'key1.key2.3.key4'`.

### Default (omitted) format

`null`, invalid.

### Examples

- `${frontmatter:{key:'tags.0'}}`: `tag1`.

## `${generatedAttachmentFileName}`

The generated file name of the attachment (available only inside [`markdownUrlFormat`](<./06 Settings.md>) setting).

### Format schema

```ts
{
  case?: 'lower' | 'upper';
  slugify?: boolean; // default: false
  trim?: {
    length: number;
    side: 'left' | 'right';
  }
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${generatedAttachmentFileName}`: `alpha/bravo/charlie.pdf -> charlie`.
- `${generatedAttachmentFileName:{case:'lower'}}`: `alpha/bravo/CHARLIE.pdf -> charlie`.
- `${generatedAttachmentFileName:{case:'upper'}}`: `alpha/bravo/charlie.pdf -> CHARLIE`.
- `${generatedAttachmentFileName:{slugify:true}}`: `alpha/bravo/charlie delta.pdf -> charlie-delta`.
- `${generatedAttachmentFileName:{trim:{side:'left',length:2}}}`: `alpha/bravo/charlie.pdf -> ch`.
- `${generatedAttachmentFileName:{trim:{side:'right',length:2}}}`: `alpha/bravo/charlie.pdf -> ie`.

## `${generatedAttachmentFilePath}`

The generated file path of the attachment (available only inside [`markdownUrlFormat`](<./06 Settings.md>) setting).

### Format schema

*(No format for this token)*.

### Default (omitted) format

`null`.

### Examples

- `${generatedAttachmentFilePath}`: `alpha/bravo/charlie.pdf`.

## `${heading}`

The heading above the cursor in the note editor where the attachment is inserted. Empty if such heading does not exist.

### Format schema

```ts
{
  level?: '1' | '2' | '3' | '4' | '5' | '6' | 'any'; // default: 'any'
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${heading}`: `Nearest heading at any level`.
- `${heading:{level:'1'}}`: `Nearest heading at level 1`.
- `${heading:{level:'2'}}`: `Nearest heading at level 2`.
- `${heading:{level:'3'}}`: `Nearest heading at level 3`.
- `${heading:{level:'4'}}`: `Nearest heading at level 4`.
- `${heading:{level:'5'}}`: `Nearest heading at level 5`.
- `${heading:{level:'6'}}`: `Nearest heading at level 6`.

## `${noteFileCreationDate}`

Note file creation date/time.

### Format schema

```ts
{
  momentJsFormat: string;
}
```

`momentJsFormat` uses [Moment.js format].

### Default (omitted) format

`null`, invalid.

### Examples

- `${noteFileCreationDate:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.

## `${noteFileModificationDate}`

Note file modification date/time.

### Format schema

```ts
{
  momentJsFormat: string;
}
```

`momentJsFormat` uses [Moment.js format].

### Default (omitted) format

`null`, invalid.

### Examples

- `${noteFileModificationDate:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.

## `${noteFileName}`

Current note file name.

### Format schema

```ts
{
  case?: 'lower' | 'upper';
  slugify?: boolean; // default: false
  trim?: {
    length: number;
    side: 'left' | 'right';
  };
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${noteFileName}`: `alpha/bravo/charlie.md -> charlie`.
- `${noteFileName:{case:'lower'}}`: `alpha/bravo/CHARLIE.md -> charlie`.
- `${noteFileName:{case:'upper'}}`: `alpha/bravo/charlie.md -> CHARLIE`.
- `${noteFileName:{slugify:true}}`: `alpha/bravo/charlie delta.md -> charlie-delta`.
- `${noteFileName:{trim:{side:'left',length:2}}}`: `alpha/bravo/charlie.md -> ch`.
- `${noteFileName:{trim:{side:'right',length:2}}}`: `alpha/bravo/charlie.md -> ie`.

## `${noteFilePath}`

Current note full path.

### Format schema

*(No format for this token)*.

### Default (omitted) format

`null`.

### Examples

- `${noteFilePath}`: `alpha/bravo/charlie.md`.

## `${noteFolderName}`

Current note's folder name.

### Format schema

```ts
{
  case?: 'lower' | 'upper';
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

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${noteFolderName}`: `alpha/bravo/charlie/delta.md -> charlie`.
- `${noteFolderName:{pick:{from:'end',index:1}}}`: `alpha/bravo/charlie/delta/echo/foxtrot.md -> delta`.
- `${noteFolderName:{pick:{from:'start',index:1}}}`: `alpha/bravo/charlie/delta/echo/foxtrot.md -> bravo`.
- `${noteFolderName:{case:'lower'}}`: `alpha/bravo/CHARLIE/delta.md -> charlie`.
- `${noteFolderName:{case:'upper'}}`: `alpha/bravo/charlie/delta.md -> CHARLIE`.
- `${noteFolderName:{slugify:true}}`: `alpha/bravo/charlie delta/echo.md -> charlie-delta`.
- `${noteFolderName:{trim:{side:'left',length:2}}}`: `alpha/bravo/charlie/delta.md -> ch`.
- `${noteFolderName:{trim:{side:'right',length:2}}}`: `alpha/bravo/charlie/delta.md -> ie`.

## `${noteFolderPath}`

Current note's folder full path.

### Format schema

*(No format for this token)*.

### Default (omitted) format

`null`.

### Examples

- `${noteFolderPath}`: `alpha/bravo/charlie.md -> alpha/bravo`.

## `${originalAttachmentFileCreationDate}`

Original attachment file creation date/time.

### Format schema

```ts
{
  momentJsFormat: string;
  valueWhenUnknown?: 'empty' | 'now'; // default: 'empty'
}
```

`momentJsFormat` uses [Moment.js format].

### Default (omitted) format

`null`, invalid.

### Examples

- `${originalAttachmentFileCreationDate:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.
- `${originalAttachmentFileCreationDate:{momentJsFormat:'YYYY-MM-DD',valueWhenUnknown:'empty'}}`: `(empty)`.

## `${originalAttachmentFileExtension}`

Extension of the original attachment file.

### Format schema

*(No format for this token)*.

### Default (omitted) format

`null`.

### Examples

- `${originalAttachmentFileExtension}`: `alpha.bravo.pdf -> pdf`.

## `${originalAttachmentFileModificationDate}`

Original attachment file modification date/time.

### Format schema

```ts
{
  momentJsFormat: string;
  valueWhenUnknown?: 'empty' | 'now'; // default: 'empty'
}
```

`momentJsFormat` uses [Moment.js format].

### Default (omitted) format

`null`, invalid.

### Examples

- `${originalAttachmentFileModificationDate:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.
- `${originalAttachmentFileModificationDate:{momentJsFormat:'YYYY-MM-DD',valueWhenUnknown:'empty'}}`: `(empty)`.

## `${originalAttachmentFileName}`

File name of the original attachment file.

### Format schema

```ts
{
  case?: 'lower' | 'upper';
  slugify?: boolean; // default: false
  trim?: {
    length: number;
    side: 'left' | 'right';
  };
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${originalAttachmentFileName}`: `alpha.pdf -> alpha`.
- `${originalAttachmentFileName:{case:'lower'}}`: `ALPHA.pdf -> alpha`.
- `${originalAttachmentFileName:{case:'upper'}}`: `alpha.pdf -> ALPHA`.
- `${originalAttachmentFileName:{slugify:true}}`: `alpha bravo.pdf -> alpha-bravo`.
- `${originalAttachmentFileName:{trim:{side:'left',length:2}}}`: `alpha.pdf -> al`.
- `${originalAttachmentFileName:{trim:{side:'right',length:2}}}`: `alpha.pdf -> ha`.

## `${prompt}`

The value asked from the user prompt.

Also in the prompt modal, you can preview the file, if it is supported by Obsidian (image, video, pdf).

### Format schema

```ts
{
  case?: 'lower' | 'upper';
  defaultValueTemplate?: string; // default: ${originalAttachmentFileName}
  slugify?: boolean; // default: false
  trim?: {
    length: number;
    side: 'left' | 'right';
  };
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${prompt}`: `alpha -> alpha`.
- `${prompt:{case:'lower'}}`: `ALPHA -> alpha`.
- `${prompt:{case:'upper'}}`: `alpha -> ALPHA`.
- `${prompt:{defaultValueTemplate:'${uuid}'}}`: shows prompt with default value as generated `${uuid}`.
- `${prompt:{slugify:true}}`: `alpha bravo -> alpha-bravo`.
- `${prompt:{trim:{side:'left',length:2}}}`: `alpha -> al`.
- `${prompt:{trim:{side:'right',length:2}}}`: `alpha -> ha`.

## `${random}`

Random value.

### Format schema

```ts
{
  digits?: boolean; // default: true
  length?: number; // default: 1
  letterCase?: 'lower' | 'mixed' | 'upper'; // default: 'upper'
  letters?: boolean; // default: true
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${random}`: `7`.
- `${random:{digits:false}}`: `M`.
- `${random:{length:10}}`: `8JR91VMU9R`.
- `${random:{letterCase:mixed,length:10}}`: `8Jr91vmU9R`.
- `${random:{letters:false}}`: `7`.

## `${sequenceNumber}`

Sequential number of the first link within the note to the attachment file. Applicable only during note rename and collecting attachments.

When the link cannot be found, the value of the token is `0`.

### Format schema

```ts
{
  length?: number; // default: 1
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${sequenceNumber}`: `1`.
- `${sequenceNumber:{length:4}}`: `0001`.

## `${uuid}`

Random UUID value.

### Format schema

```ts
{
  case?: 'lower' | 'upper'; // default: 'lower'
  hyphens?: boolean; // default: true
}
```

### Default (omitted) format

`null`, equivalent to `{}`.

### Examples

- `${uuid}`: `edd5b990-fede-4e02-aa0e-1e9251da2f83`.
- `${uuid:{case:'upper'}}`: `EDD5B990-FEDE-4E02-AA0E-1E9251DA2F83`.
- `${uuid:{hyphens:false}}`: `edd5b990fede4e02aa0e1e9251da2f83`.

[Moment.js format]: https://momentjs.com/docs/#/displaying/format/
