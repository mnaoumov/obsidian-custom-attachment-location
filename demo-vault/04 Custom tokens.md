# Custom tokens

When the built-in tokens (see [03 Tokens and patterns](<./03 Tokens and patterns.md>)) are not enough, you can define your **own** tokens as JavaScript functions - both synchronous and asynchronous are supported. They are stored in the `customTokensStr` setting and edited under **Settings -> Community plugins -> `Custom Attachment Location` -> Custom tokens**.

## Example

```javascript
registerCustomToken('alpha', (ctx) => {
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  return ctx.noteFileName + ctx.app.appId + formatValue + ctx.obsidian.apiVersion;
});

registerCustomToken('bravo', async (ctx) => {
  await sleep(100);
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  return ctx.noteFileName + formatValue;
});
```

After registering them, you can use `{{alpha}}` and `{{bravo:{formatKey:'charlie'}}}` in any pattern - the same three settings that accept built-in tokens: `attachmentFolderPath`, `generatedAttachmentFileName`, and `markdownUrlFormat`.

## Try it

1. Open **Settings -> Community plugins -> `Custom Attachment Location` -> Custom tokens** and paste a `registerCustomToken(...)` block.
2. Set **Generated attachment file name** to a pattern using your token, e.g. `{{alpha}}`.
3. Paste an image and watch the generated name.

The first button does steps 1 and 2 with the example above. It replaces whatever is in **Custom tokens**, so copy your own tokens somewhere first if you have any. It also restarts the plugin once: the settings tab registers a token as you type it, but a token saved any other way is only registered when the plugin loads.

```code-button
---
caption: Register alpha and bravo, and name attachments with {{alpha}}
---
await require('/demoSetup.ts').registerExampleTokens(app);
```

The next two stand in for step 3. One asks where a pasted image would go and what it would be called, and the other saves a sample image as an attachment of this note under that name:

```code-button
---
caption: What would a pasted image be called?
---
await require('/demoSetup.ts').previewAttachmentPath(app);
```

```code-button
---
caption: Save a sample image named by {{alpha}}
---
await require('/demoSetup.ts').saveSampleAttachment(app, { kind: 'image' });
```

The name is this note's name, the app id, `defaultFormatValue` and the API version, run together. To put things back:

```code-button
---
caption: Remove the example tokens
---
await require('/demoSetup.ts').removeExampleTokens(app);
```

Manual equivalent: the three steps above, then empty **Custom tokens** and set **Generated attachment file name** back to `file-{{date:{momentJsFormat:'YYYYMMDDHHmmssSSS'}}}`.

The `ctx` argument exposes the note, the attachment, the app, and a `ctx.fillTemplate(...)` helper that resolves a pattern of its own from inside your token:

```javascript
registerCustomToken('bravo', async (ctx) => {
  const filledTemplate = await ctx.fillTemplate('delta {{echo}} foxtrot {{golf:{hotel:\'india\'}}} juliett');
  return ctx.noteFileName + filledTemplate;
});
```

Its full shape is documented in the plugin's [`token-evaluator-context.ts`](https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/main/src/tokens/token-evaluator-context.ts).

## Worked example: rename only images, keep every other file's name

`attachmentRenameMode` decides *which gesture* renames a file (`None`, `Only pasted images`, `All`), not *which kind* of file. To rename images and leave a PDF, a ZIP or an audio file with the name it came with, let a token decide by extension:

```javascript
registerCustomToken('imagesOnly', async (ctx) => {
  const imageExtensions = ['avif', 'bmp', 'gif', 'jpeg', 'jpg', 'png', 'svg', 'webp'];
  if (!imageExtensions.includes(ctx.attachmentFileExtension.toLowerCase())) {
    return ctx.attachmentFileName;
  }

  return await ctx.fillTemplate('{{noteFileName}}-{{date:YYYYMMDDHHmmssSSS}}');
});
```

Then:

1. Set **Attachment rename mode** (`attachmentRenameMode`) to `All`, so a dropped or imported image goes through the pattern too, not only a pasted one.
2. Set **Generated attachment file name** to `{{imagesOnly}}`.

The first button registers the token and does both steps. The other two save a sample image and a sample PDF as attachments of this note: the image gets this note's name and a timestamp, and the PDF keeps its name, `report-2026.pdf`.

```code-button
---
caption: Register imagesOnly and turn on its two settings
---
await require('/demoSetup.ts').registerImagesOnlyToken(app);
```

```code-button
---
caption: Save a sample image through imagesOnly
---
await require('/demoSetup.ts').saveSampleAttachment(app, { kind: 'image' });
```

```code-button
---
caption: Save a sample PDF through imagesOnly
---
await require('/demoSetup.ts').saveSampleAttachment(app, { kind: 'pdf' });
```

**Remove the example tokens** above puts all three settings back. Manual equivalent: paste the token into **Custom tokens**, do the two steps, then paste an image and drag a PDF into a note.

`ctx.attachmentFileName` is the attachment's name as it is now, **without** its extension, and `ctx.attachmentFileExtension` is its extension without the dot. While a file is being saved that is the incoming file's. `ctx.originalAttachmentFileName` and `ctx.originalAttachmentFileExtension` are the name and extension it arrived with, which differ once the file has been renamed; a token that reads them gets the same fallback, and the same warning, as the built-in token. The plugin adds the extension back itself, so neither branch returns one. Swap the `fillTemplate` pattern for whatever an image should be called, and the list for the extensions that count as images to you; to do the reverse - keep the original names of a few types, say `pdf`, and rename the rest - flip the test to `['pdf'].includes(...)`.

## Reading the attachment's bytes

`ctx.attachmentFileContent` (synchronous) was replaced by the lazy async `ctx.getAttachmentFileContent()`. Reading an attachment's bytes costs more the larger the file is, so they are now read on demand, only when a token actually asks for them, and never for the built-in tokens. Migrate a token that needs the content like this:

```javascript
// Before
registerCustomToken('size', (ctx) => String(ctx.attachmentFileContent?.byteLength ?? 0));

// After
registerCustomToken('size', async (ctx) => {
  const content = await ctx.getAttachmentFileContent();
  return String(content?.byteLength ?? 0);
});
```
