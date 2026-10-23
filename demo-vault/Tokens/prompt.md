# `{{prompt}}`

The value asked from the user prompt.

The modal opens with the input already focused and the pre-filled value selected, so you can type the new name straight away - the first keystroke replaces what is there. `defaultValueTemplate` controls what it is pre-filled with; set it to something other than the attachment's own name if you would rather start from [`{{uuid}}`](<./uuid.md>), [`{{date}}`](<./date.md>), or anything else.

The heading names what you are deciding: **Rename attachment file** when `{{prompt}}` sits in the generated file name, **Choose attachment folder** when it sits in the attachment folder path. The second line shows the whole template with the current token highlighted.

Also in the prompt modal, you can preview the file, if it is supported by Obsidian (image, video, pdf).

One of the tokens in [09 Token reference](<../09 Token reference.md>), which also covers the format syntax and validation every token shares.

## Format schema

```ts
{
  case?: 'lower' | 'title' | 'upper';
  collapseWhitespace?: boolean; // default: false
  defaultValueTemplate?: string; // default: {{originalAttachmentFileName}}
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

- `{{prompt}}`: `alpha -> alpha`.
- `{{prompt:{case:'lower'}}}`: `ALPHA -> alpha`.
- `{{prompt:{case:'title'}}}`: `my REPORT about api -> My REPORT About Api` - the first letter of each word, except a word that is already entirely upper case, which is left alone so an acronym survives.
- `{{prompt:{case:'upper'}}}`: `alpha -> ALPHA`.
- `{{prompt:{collapseWhitespace:true}}}`: `[   alpha    bravo   ] -> [alpha bravo]` (brackets shown only to make the spaces visible) - every run of whitespace becomes one space, and the ends are stripped.
- `{{prompt:{case:'title',collapseWhitespace:true}}}`: `[  my   REPORT about  api  ] -> [My REPORT About Api]` - the two compose, which is the whole cleaning together.
- `{{prompt:{defaultValueTemplate:'{{uuid}}'}}}`: shows prompt with default value as generated `{{uuid}}`.
- `{{prompt:{slugify:true}}}`: `alpha bravo -> alpha-bravo`.
- `{{prompt:{trim:{side:'left',length:2}}}}`: `alpha -> al`.
- `{{prompt:{trim:{side:'right',length:2}}}}`: `alpha -> ha`.
