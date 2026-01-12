# Custom Attachment Location

This is a plugin for [Obsidian](https://obsidian.md/) that allows to customize attachment location with tokens (`${noteFileName}`, `${date:{momentJsFormat:'YYYYMMDD'}}`, etc) like typora.

## Features

- Modify location for attachment folder.
- Modify file name for **Pasted Files**.
- **Collect attachments** - take all attachments from the notes and puts them into the corresponding configured folders.

## Settings

### Location for new attachments

- Same to "Files & Links -> Default location for new attachments".
- **Put "./" at the beginning of the path if you want to use relative path.**
- See available [tokens](#tokens).
- example: `assets/${noteFileName}`, `./assets/${noteFileName}`, `./assets/${noteFileName}/${date:{momentJsFormat:'YYYY'}}`

> [!WARNING]
>
> Other plugins might intercept attachment insertion and use their own locations, which might seem that this plugin is misbehaving. See [#7](https://github.com/mnaoumov/obsidian-custom-attachment-location/issues/7).

### Generated attachment file name

- See available [tokens](#tokens).
- example: `${originalAttachmentFileName}-${date:{momentJsFormat:'YYYYMMDDHHmmssSSS'}}`, `${noteFileName}-img-${date:{momentJsFormat:'YYYYMMDD'}}`
- Obsidian default: `Pasted image ${date:{momentJsFormat:'YYYYMMDDHHmmss'}}`.

> [!WARNING]
>
> Other plugins might intercept attachment insertion and use their own file names, which might seem that this plugin is misbehaving. See [#7](https://github.com/mnaoumov/obsidian-custom-attachment-location/issues/7).

### Markdown URL format

Format for the URL that will be inserted into Markdown.

- See available [tokens](#tokens).

> [!WARNING]
>
> This setting is needed for very specific [use cases](https://github.com/RainCat1998/obsidian-custom-attachment-location/pull/152). For majority of users, it should stay blank.
>
> - If set, all links to attachments will be created as markdown links, even if Obsidian settings are configured to use `[[Wikilinks]]`.
> - If set to `${generatedAttachmentFilePath}`, it is almost the same as leaving it blank, considering the previous bullet point. Leave this setting blank instead, unless you want to enforce markdown links, regardless of native Obsidian settings.
> - If set to `${noteFilePath}`, will insert a link to the note itself, instead of the attachment files, which is not what you want. Some users reported they have this incorrect value set automatically during the invalid update. To fix the issue, leave this setting blank (or set to something meaningful).

### Should rename attachment folder

Automatically update attachment folder name if [Location for New Attachments](#location-for-new-attachments) contains `${noteFileName}`.

### Should rename attachment files

Automatically update attachment files in target md file if [Generated attachment file name](#generated-attachment-file-name) contains `${noteFileName}`.

### Special characters replacement

Automatically replace special characters in attachment folder and file name with the specified string.

### Should rename attachments to lowercase

Automatically set all characters in folder name and pasted image name to be lowercase.

### Should convert pasted images to JPEG

Paste images from clipboard converting them to JPEG.

### JPEG Quality

The smaller the quality, the greater the compression ratio.

### Convert images on drag&drop

If enabled and `Convert pasted images to JPEG` setting is enabled, images drag&dropped into the editor will be converted to JPEG.

### Rename only images

If enabled, only image files will be renamed.

If disabled, all attachment files will be renamed.

### Rename pasted files with known names

If enabled, pasted copied files with known names will be renamed.

If disabled, only clipboard image objects (e.g., screenshots) will be renamed.

### Rename attachments on drag&drop

If enabled, attachments dragged and dropped into the editor will be renamed according to the [Generated attachment file name](#generated-attachment-file-name) setting.

### Should rename collected attachments

If enabled, attachments processed via `Collect attachments` commands will be renamed according to the [Generated attachment file name](#generated-attachment-file-name) setting.

### Duplicate name separator

When you are pasting/dragging a file with the same name as an existing file, this separator will be added to the file name.

E.g., when you are dragging file `existingFile.pdf`, it will be renamed to `existingFile 1.pdf`, `existingFile 2.pdf`, etc, getting the first name available.

Default value is `␣` (`space`).

### Should keep empty attachment folders

If enabled, empty attachment folders will be preserved, useful for source control purposes.

### Should delete orphan attachments

If enabled, when the note is deleted, its orphan attachments are deleted as well.

## Tokens

The following tokens can be used in the [Location for New Attachments](#location-for-new-attachments), [Generated attachment file name](#generated-attachment-file-name) and [Markdown URL format](#markdown-url-format) settings.

Token strings:

- `${token}`: Use token default format (`null`).
- `${token:{...}}`: Use explicit format parsed as a **JSON5 object** (single-line).

`token` is case-insensitive. Format object keys and values are case-sensitive.

### Format (JSON5)

The `<format>` part must be a JSON5 **object** (single line), i.e. it must start with `{` and end with `}`.

- Property names can be quoted or unquoted: `${attachmentFileSize:{unit:'KB','decimalPoints':2}}`.
- Strings must be quoted: `${date:{momentJsFormat:'YYYYMMDD'}}`.
- JSON5 allows (optional) trailing commas: `${attachmentFileSize:{unit:'KB',decimalPoints:2,}}`.

If you need quotes inside a JSON5 string, either escape them or switch quote types:

- `${date:{momentJsFormat:'YYYY-MM-DD \'at\' HH:mm'}}`
- `${date:{momentJsFormat:"YYYY-MM-DD 'at' HH:mm"}}`

### Validation (strict)

Each token validates its own `format` shape at runtime. Unknown object properties are rejected (strict validation).

Example (error):

`❌ ${attachmentFileSize:{unit:'B',decimalPoints:3,unknownProperty:'foo'}}`

### `${attachmentFileSize}`

Size of the attachment file.

#### Format schema

```ts
{
  decimalPoints?: number; // default: 0
  unit?: 'B' | 'KB' | 'MB'; // default: 'B'
}
```

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${attachmentFileSize}`: `123`.
- `${attachmentFileSize:{unit:'KB',decimalPoints:2}}`: `456.78`.

### `${date}`

Current date/time.

#### Format schema

```ts
{
  momentJsFormat: string;
}
```

#### Default (omitted) format

`null`, invalid.

#### Examples

- `${date:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.

### `${frontmatter}`

Frontmatter value of the current note.

#### Format schema

```ts
{
  key: string;
}
```

Nested keys are supported, e.g. `'key1.key2.3.key4'`.

#### Default (omitted) format

`null`, invalid.

#### Examples

- `${frontmatter:{key:'tags.0'}}`: `tag1`.

### `${generatedAttachmentFileName}`

The generated file name of the attachment (available only inside [Markdown URL format](#markdown-url-format) setting).

#### Format schema

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

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${generatedAttachmentFileName}`: `foo/bar/baz.pdf -> baz`.
- `${generatedAttachmentFileName:{case:'lower'}}`: `foo/bar/BAZ.pdf -> baz`.
- `${generatedAttachmentFileName:{case:'upper'}}`: `foo/bar/baz.pdf -> BAZ`.
- `${generatedAttachmentFileName:{slugify:true}}`: `foo/bar/baz qux.pdf -> baz-qux`.
- `${generatedAttachmentFileName:{trim:{side:'left',length:2}}}`: `foo/bar/baz.pdf -> ba`.
- `${generatedAttachmentFileName:{trim:{side:'right',length:2}}}`: `foo/bar/baz.pdf -> az`.

### `${generatedAttachmentFilePath}`

The generated file path of the attachment (available only inside [Markdown URL format](#markdown-url-format) setting).

#### Format schema

*(No format for this token)*.

#### Default (omitted) format

`null`.

#### Examples

- `${generatedAttachmentFilePath}`: `foo/bar/baz.pdf`.

### `${heading}`

The heading above the cursor in the note editor where the attachment is inserted. Empty if such heading does not exist.

#### Format schema

```ts
{
  level?: '1' | '2' | '3' | '4' | '5' | '6' | 'any'; // default: 'any'
}
```

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${heading}`: `Nearest heading at any level`.
- `${heading:{level:'1'}}`: `Nearest heading at level 1`.
- `${heading:{level:'2'}}`: `Nearest heading at level 2`.
- `${heading:{level:'3'}}`: `Nearest heading at level 3`.
- `${heading:{level:'4'}}`: `Nearest heading at level 4`.
- `${heading:{level:'5'}}`: `Nearest heading at level 5`.
- `${heading:{level:'6'}}`: `Nearest heading at level 6`.

### `${noteFileCreationDate}`

Note file creation date/time.

#### Format schema

```ts
{
  momentJsFormat: string;
}
```

`momentJsFormat` uses [Moment.js format].

#### Default (omitted) format

`null`, invalid.

#### Examples

- `${noteFileCreationDate:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.

### `${noteFileModificationDate}`

Note file modification date/time.

#### Format schema

```ts
{
  momentJsFormat: string;
}
```

`momentJsFormat` uses [Moment.js format].

#### Default (omitted) format

`null`, invalid.

#### Examples

- `${noteFileModificationDate:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.

### `${noteFileName}`

Current note file name.

#### Format schema

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

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${noteFileName}`: `foo/bar/baz.md -> baz`.
- `${noteFileName:{case:'lower'}}`: `foo/bar/BAZ.md -> baz`.
- `${noteFileName:{case:'upper'}}`: `foo/bar/baz.md -> BAZ`.
- `${noteFileName:{slugify:true}}`: `foo/bar/baz qux.md -> baz-qux`.
- `${noteFileName:{trim:{side:'left',length:2}}}`: `foo/bar/baz.md -> ba`.
- `${noteFileName:{trim:{side:'right',length:2}}}`: `foo/bar/baz.md -> az`.

### `${noteFilePath}`

Current note full path.

#### Format schema

*(No format for this token)*.

#### Default (omitted) format

`null`.

#### Examples

- `${noteFilePath}`: `foo/bar/baz.md`.

### `${noteFolderName}`

Current note's folder name.

#### Format schema

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

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${noteFolderName}`: `foo/bar/baz/qux.md -> baz`.
- `${noteFolderName:{pick:{from:'end',index:1}}}`: `foo/bar/baz/qux/quux/corge.md -> qux`.
- `${noteFolderName:{pick:{from:'start',index:1}}}`: `foo/bar/baz/qux/quux/corge.md -> bar`.
- `${noteFolderName:{case:'lower'}}`: `foo/bar/BAZ/qux.md -> baz`.
- `${noteFolderName:{case:'upper'}}`: `foo/bar/baz/qux.md -> BAZ`.
- `${noteFolderName:{slugify:true}}`: `foo/bar/baz qux/quux.md -> baz-qux`.
- `${noteFolderName:{trim:{side:'left',length:2}}}`: `foo/bar/baz/qux.md -> ba`.
- `${noteFolderName:{trim:{side:'right',length:2}}}`: `foo/bar/baz/qux.md -> az`.

### `${noteFolderPath}`

Current note's folder full path.

#### Format schema

*(No format for this token)*.

#### Default (omitted) format

`null`.

#### Examples

- `${noteFolderPath}`: `foo/bar/baz.md -> foo/bar`.

### `${originalAttachmentFileCreationDate}`

Original attachment file creation date/time.

#### Format schema

```ts
{
  momentJsFormat: string;
  valueWhenUnknown?: 'empty' | 'now'; // default: 'empty'
}
```

`momentJsFormat` uses [Moment.js format].

#### Default (omitted) format

`null`, invalid.

#### Examples

- `${originalAttachmentFileCreationDate:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.
- `${originalAttachmentFileCreationDate:{momentJsFormat:'YYYY-MM-DD',valueWhenUnknown:'empty'}}`: `(empty)`.

### `${originalAttachmentFileExtension}`

Extension of the original attachment file.

#### Format schema

*(No format for this token)*.

#### Default (omitted) format

`null`.

#### Examples

- `${originalAttachmentFileExtension}`: `foo.bar.pdf -> pdf`.

### `${originalAttachmentFileModificationDate}`

Original attachment file modification date/time.

#### Format schema

```ts
{
  momentJsFormat: string;
  valueWhenUnknown?: 'empty' | 'now'; // default: 'empty'
}
```

`momentJsFormat` uses [Moment.js format].

#### Default (omitted) format

`null`, invalid.

#### Examples

- `${originalAttachmentFileModificationDate:{momentJsFormat:'YYYY-MM-DD'}}`: `2025-12-31`.
- `${originalAttachmentFileModificationDate:{momentJsFormat:'YYYY-MM-DD',valueWhenUnknown:'empty'}}`: `(empty)`.

### `${originalAttachmentFileName}`

File name of the original attachment file.

#### Format schema

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

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${originalAttachmentFileName}`: `foo.pdf -> foo`.
- `${originalAttachmentFileName:{case:'lower'}}`: `FOO.pdf -> foo`.
- `${originalAttachmentFileName:{case:'upper'}}`: `foo.pdf -> FOO`.
- `${originalAttachmentFileName:{slugify:true}}`: `foo bar.pdf -> foo-bar`.
- `${originalAttachmentFileName:{trim:{side:'left',length:2}}}`: `foo.pdf -> fo`.
- `${originalAttachmentFileName:{trim:{side:'right',length:2}}}`: `foo.pdf -> oo`.

### `${prompt}`

The value asked from the user prompt.

Also in the prompt modal, you can preview the file, if it is supported by Obsidian (image, video, pdf).

#### Format schema

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

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${prompt}`: `foo -> foo`.
- `${prompt:{case:'lower'}}`: `FOO -> foo`.
- `${prompt:{case:'upper'}}`: `foo -> FOO`.
- `${prompt:{defaultValueTemplate:'${uuid}'}}`: shows prompt with default value as generated `${uuid}`.
- `${prompt:{slugify:true}}`: `foo bar -> foo-bar`.
- `${prompt:{trim:{side:'left',length:2}}}`: `foo -> fo`.
- `${prompt:{trim:{side:'right',length:2}}}`: `foo -> oo`.

### `${random}`

Random value.

#### Format schema

```ts
{
  digits?: boolean; // default: true
  length?: number; // default: 1
  letterCase?: 'lower' | 'mixed' | 'upper'; // default: 'upper'
  letters?: boolean; // default: true
}
```

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${random}`: `7`.
- `${random:{digits:false}}`: `M`.
- `${random:{length:10}}`: `8JR91VMU9R`.
- `${random:{letterCase:mixed,length:10}}`: `8Jr91vmU9R`.
- `${random:{letters:false}}`: `7`.

### `${sequenceNumber}`

Sequential number of the first link within the note to the attachment file. Applicable only during note rename and collecting attachments.

When the link cannot be found, the value of the token is `0`.

#### Format schema

```ts
{
  length?: number; // default: 1
}
```

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${sequenceNumber}`: `1`.
- `${sequenceNumber:{length:4}}`: `0001`.

### `${uuid}`

Random UUID value.

#### Format schema

```ts
{
  case?: 'lower' | 'upper'; // default: 'lower'
  hyphens?: boolean; // default: true
}
```

#### Default (omitted) format

`null`, equivalent to `{}`.

#### Examples

- `${uuid}`: `edd5b990-fede-4e02-aa0e-1e9251da2f83`.
- `${uuid:{case:'upper'}}`: `EDD5B990-FEDE-4E02-AA0E-1E9251DA2F83`.
- `${uuid:{hyphens:false}}`: `edd5b990fede4e02aa0e1e9251da2f83`.

## Custom tokens

You can define custom tokens in the `Custom tokens` setting.

The custom tokens are defined as functions, both sync and async are supported.

Example:

```javascript
registerCustomToken('foo', (ctx) => {
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  return ctx.noteFileName + ctx.app.appId + formatValue + ctx.obsidian.apiVersion;
});

registerCustomToken('bar', async (ctx) => {
  await sleep(100);
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  const filledTemplate = await ctx.fillTemplate('qux ${quux} corge ${grault:{garply:\'waldo\'}} fred');
  return ctx.noteFileName + ctx.app.appId + formatValue + ctx.obsidian.apiVersion + filledTemplate;
});
```

Then you can use the defined `${foo}`, `${bar:{formatKey:'baz'}}` tokens in the [Location for New Attachments](#location-for-new-attachments), [Generated attachment file name](#generated-attachment-file-name) and [Markdown URL format](#markdown-url-format) settings.

See [spec](./src/TokenEvaluatorContext.ts) of the `ctx` argument.

## Changelog

All notable changes to this project will be documented in the [CHANGELOG](./CHANGELOG.md).

## Installation

The plugin is available in [the official Community Plugins repository](https://obsidian.md/plugins?id=obsidian-custom-attachment-location).

### Beta versions

To install the latest beta release of this plugin (regardless if it is available in [the official Community Plugins repository](https://obsidian.md/plugins) or not), follow these steps:

1. Ensure you have the [BRAT plugin](https://obsidian.md/plugins?id=obsidian42-brat) installed and enabled.
2. Click [Install via BRAT](https://intradeus.github.io/http-protocol-redirector?r=obsidian://brat?plugin=https://github.com/mnaoumov/obsidian-custom-attachment-location).
3. An Obsidian pop-up window should appear. In the window, click the `Add plugin` button once and wait a few seconds for the plugin to install.

## Debugging

By default, debug messages for this plugin are hidden.

To show them, run the following command:

```js
window.DEBUG.enable('obsidian-custom-attachment-location');
```

For more details, refer to the [documentation](https://github.com/mnaoumov/obsidian-dev-utils/blob/main/docs/debugging.md).

## Support

<!-- markdownlint-disable MD033 -->
<a href="https://www.buymeacoffee.com/mnaoumov" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="60" width="217"></a>
<!-- markdownlint-enable MD033 -->

## Attributions

[In Oct 2021](https://github.com/RainCat1998/obsidian-custom-attachment-location/commit/1c92b85f7a5eba71cf54e20452eb8f3c2404a273), the plugin was created by [RainCat1998](https://github.com/RainCat1998).

[From July 2024](https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/59), the plugin is maintained by [Michael Naumov](https://github.com/mnaoumov/).

From December 2025, the project repository is hosted at [mnaoumov/obsidian-custom-attachment-location](https://github.com/mnaoumov/obsidian-custom-attachment-location).

The original author's repository is preserved as an archive of issues/PRs/discussions/releases at [RainCat1998/obsidian-custom-attachment-location](https://github.com/RainCat1998/obsidian-custom-attachment-location).

## License

Copyright (c) [RainCat1998](https://github.com/RainCat1998), [Michael Naumov](https://github.com/mnaoumov/).

[Moment.js format]: https://momentjs.com/docs/#/displaying/format/
