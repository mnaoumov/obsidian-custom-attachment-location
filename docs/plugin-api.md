# Plugin API

Everything this plugin offers another plugin is declared in one hand-written file — [api.d.ts](../api.d.ts) at the repository root. It imports from `obsidian` and nothing else, so you can copy it into your own code or reference it where it sits, with no build-time dependency on this repository.

The API is published through the `@mnaoumov/obsidian-lib` plugin registry under the plugin id `obsidian-custom-attachment-location`, so you get version negotiation, a handle that is revoked when this plugin unloads, and a wait that ends when it loads rather than a lookup that returns `undefined` because it ran first. The contract version is `1.3.0` and moves independently of the plugin's own version, so pin a range against the contract, not against a release.

Beside `api.d.ts`, [`api-contract.ts`](../api-contract.ts) holds the API's contract, `CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT`: for every method, a schema over its arguments and a schema over what it returns. It is the constant this plugin publishes with the API, so copy it next to `api.d.ts` and pass it as the `contract`, and both sides check the same definition. Its schemas are [Standard Schema](https://standardschema.dev) objects built with [`@mnaoumov/typescript-lib/api-contract`](https://www.npmjs.com/package/@mnaoumov/typescript-lib), which carries the generic half (the contract types, the schema builders and the guard builders), and its file guards come from [`@mnaoumov/obsidian-lib`](https://www.npmjs.com/package/@mnaoumov/obsidian-lib), so copying it means adding both packages (`npm install @mnaoumov/typescript-lib @mnaoumov/obsidian-lib`, typescript-lib `1.3.0` or later). Apart from those two, the file imports only `obsidian` and `./api.d.ts`. (It is not named `api.ts`: TypeScript would read `api.d.ts` as that file's own declarations.)

If your plugin already uses [`@mnaoumov/obsidian-lib`](https://mnaoumov.dev/obsidian-lib/guides/cross-plugin-apis/), `watchPluginApi` is the whole of it:

```ts
const apiRef = watchPluginApi<CustomAttachmentLocationApi>({
  apiVersionRange: '^1',
  app,
  component: this,
  contract: CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT,
  pluginId: 'obsidian-custom-attachment-location'
});

const folder = await apiRef.value?.getAttachmentFolderPath({ notePath: 'Notes/Alpha.md' });
const properPath = await apiRef.value?.getProperAttachmentPath({ attachmentPathOrFile: 'image.png', notePath: 'Notes/Alpha.md' });
```

If your plugin does not use `@mnaoumov/obsidian-lib` — and is not going to — you still need no dependency on anything. The registry, and the two events a plugin announces itself through, are a documented wire protocol reachable with the `obsidian` module alone; [Plugin API protocol](https://mnaoumov.dev/obsidian-lib/guides/plugin-api-protocol/) is that route written out, and `api.d.ts` types it just as well, since nothing in that file imports the library either. Only the contract takes packages, and the raw route works without it. Look the API up each time you use it rather than keeping it in a field: the raw object does not know when this plugin has unloaded.

## Do not read `vault.getConfig('attachmentFolderPath')`

This plugin patches that call, which makes it look like the seam you want. It is not one. The patch answers with this plugin's value only while a note is open, and the value it answers with is **the open note's** — computed once when the file was opened. A plugin looping over every note in the vault therefore gets the active note's attachment folder for all of them, silently, with no error and nothing to distinguish it from a correct answer. The patch is a write-path override for Obsidian's own attachment creation, not a readable configuration.

`getAttachmentFolderPath` is the read, asked once per note. It answers `null` when this plugin leaves that note alone entirely, which is your cue to fall back to Obsidian's own `attachmentFolderPath` — a different answer from this plugin not being installed, and deliberately so.

Both reads arrived in contract version `1.0.0`, and both are asynchronous: an attachment folder is the result of evaluating a user-written template whose tokens can read the note's frontmatter and the attachment's bytes, so there is no synchronous answer to hand back. Neither ever asks the user anything, so a whole-vault audit raises no dialogs.

## Collecting a note's attachments

`collectAttachments`, added in contract version `1.2.0` (ask for `'^1.2.0'`), collects the attachments of the notes and folders you name, the way the `Collect attachments` commands do, without opening the note first:

```ts
await apiRef.value?.collectAttachments({ pathsOrFiles: ['Notes/Alpha.md'] });
```

It is an action, not a read, so it asks what the command asks: it confirms several files or a folder with the user, and it follows the user's settings for an attachment several notes share. The promise settles once the collect has finished, queued behind any collect already running. It replaces reaching into the plugin instance for `collectAttachmentsInAbstractFiles`, which still works but is superseded.

## Moving attachments the way this plugin would

Two members added in contract version `1.3.0` (ask for `'^1.3.0'`) serve a plugin that moves or deletes attachments on a note's behalf and wants to follow this plugin's policy:

```ts
const attachmentPath = await apiRef.value?.getAvailablePathForAttachments({
  attachmentFileBaseName: 'image',
  attachmentFileExtension: 'png',
  context: 'RenameNote',
  notePathOrFile: 'Notes/Renamed.md',
  oldAttachmentPathOrFile: 'Attachments/Alpha/image.png',
  oldNotePathOrFile: 'Notes/Alpha.md',
  readAttachmentFileContent: null,
  shouldSkipMissingAttachmentFolderCreation: true
});

const isUnitFolder = apiRef.value?.isAttachmentUnitFolder({ folderPath: 'Notes/page_files' });
```

`getAvailablePathForAttachments` is this plugin's full resolver, with the options `Vault.getAvailablePathForAttachments` cannot express: the note's old path during a rename, the attachment's bytes for a template that hashes them, and whether to keep the file name or skip the duplicate check. Its params are the same fields as `@mnaoumov/obsidian-lib`'s `GetAvailablePathForAttachmentsExtendedFunctionParams`. It acts for the caller, so a `{{prompt}}` token may ask the user. `isAttachmentUnitFolder` says whether the user designated a folder whose whole hierarchy travels as one attachment, and is synchronous.

Both replace the `extended` and `checkIsAttachmentUnitFolder` members this plugin used to graft onto `app.vault.getAvailablePathForAttachments`. Those were removed in 15.0.0.

## Handing collect settings over

A plugin that used to collect attachments itself hands its settings over through `migrateSettings`, added in contract version `1.1.0`, so ask for `'^1.1.0'`. It proposes the values it held, and this plugin shows the user each one that would change next to the value it holds now. Nothing is written unless the user approves, and `isApplied: false` means they cancelled, so keep the proposal pending. `api.d.ts` lists the settings that can be proposed. The shape matches `@mnaoumov/obsidian-lib`'s `SettingsMigrationApi`, so its `SettingsMigrationComponent` can run the whole offer:

```ts
this.addChild(new SettingsMigrationComponent<MigratableCollectSettings>({
  apiVersionRange: '^1.1.0',
  app,
  getProposedSettings: () => settingsComponent.settings.proposedCollectSettings,
  pluginSettingsComponent: settingsComponent,
  providerPluginId: 'obsidian-custom-attachment-location',
  retireProposedSettings: () => settingsComponent.editAndSave((settings) => {
    settings.proposedCollectSettings = null;
  }),
  sourcePluginId: this.manifest.id
}));
```
