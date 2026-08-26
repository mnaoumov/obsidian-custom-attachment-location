# Custom tokens

When the built-in tokens (see [03 Tokens and patterns](<./03 Tokens and patterns.md>)) are not enough, you can define your **own** tokens as JavaScript functions - both synchronous and asynchronous are supported. They are stored in the `customTokensStr` setting and edited under **Settings -> Community plugins -> Custom Attachment Location -> Custom tokens**.

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

After registering them, you can use `${alpha}` and `${bravo:{formatKey:'charlie'}}` in any pattern - the same three settings that accept built-in tokens: `attachmentFolderPath`, `generatedAttachmentFileName`, and `markdownUrlFormat`.

## Try it

1. Open **Settings -> Community plugins -> Custom Attachment Location -> Custom tokens** and paste a `registerCustomToken(...)` block.
2. Set **Generated attachment file name** to a pattern using your token, e.g. `${alpha}`.
3. Paste an image (you supply the file) and watch the generated name.

The `ctx` argument exposes the note, the attachment, the app, and a `ctx.fillTemplate(...)` helper that resolves a pattern of its own from inside your token:

```javascript
registerCustomToken('bravo', async (ctx) => {
  const filledTemplate = await ctx.fillTemplate('delta ${echo} foxtrot ${golf:{hotel:\'india\'}} juliett');
  return ctx.noteFileName + filledTemplate;
});
```

Its full shape is documented in the plugin's [`token-evaluator-context.ts`](https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/main/src/token-evaluator-context.ts).

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
