# Custom tokens

When the built-in tokens (see [03 Tokens and patterns](<./03 Tokens and patterns.md>)) are not enough, you can define your **own** tokens as JavaScript functions - both synchronous and asynchronous are supported. They are stored in the `customTokensStr` setting and edited under **Settings -> Community plugins -> Custom Attachment Location -> Custom tokens**.

## Example

```javascript
registerCustomToken('foo', (ctx) => {
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  return ctx.noteFileName + ctx.app.appId + formatValue + ctx.obsidian.apiVersion;
});

registerCustomToken('bar', async (ctx) => {
  await sleep(100);
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  return ctx.noteFileName + formatValue;
});
```

After registering them, you can use `${foo}` and `${bar:{formatKey:'baz'}}` in any pattern - the same three settings that accept built-in tokens: `attachmentFolderPath`, `generatedAttachmentFileName`, and `markdownUrlFormat`.

## Try it

1. Open **Settings -> Community plugins -> Custom Attachment Location -> Custom tokens** and paste a `registerCustomToken(...)` block.
2. Set **Generated attachment file name** to a pattern using your token, e.g. `${foo}`.
3. Paste an image (you supply the file) and watch the generated name.

The `ctx` argument exposes the note, the attachment, the app, and a `ctx.fillTemplate(...)` helper. Its full shape is documented in the plugin's [`token-evaluator-context.ts`](https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/main/src/token-evaluator-context.ts).
