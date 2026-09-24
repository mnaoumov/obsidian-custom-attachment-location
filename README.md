# Custom Attachment Location

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/mnaoumov) [![GitHub release](https://img.shields.io/github/v/release/mnaoumov/obsidian-custom-attachment-location)](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases) [![GitHub downloads](https://img.shields.io/github/downloads/mnaoumov/obsidian-custom-attachment-location/total)](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases) [![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/mnaoumov/obsidian-custom-attachment-location)

Paste a screenshot into [Obsidian](https://obsidian.md/) and it lands in one shared attachment folder under a name like `Pasted image 20250101120000`. A year later that folder holds a thousand files whose names say nothing about which note they belong to, and moving or renaming a note leaves its attachments behind. This plugin lets you decide **where** each attachment is stored and **what** it is called, from a pattern built out of tokens — `${noteFileName}`, `${date:{momentJsFormat:'YYYYMMDD'}}`, and about twenty more — and then keeps that arrangement true as notes are renamed, moved and deleted. The renaming and deleting half is handled by its companion plugin, [Advanced Rename and Delete Handler](https://obsidian.md/plugins?id=advanced-rename-and-delete-handler), which this plugin requires: it does nothing until that plugin is installed, and installs it for you in one click.

<!-- markdownlint-disable MD033 -->

<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-1.png"><img src="images/screenshots/screenshot-desktop-1.png" alt="Every pasted screenshot in one heap, named after the clock" width="600"></a>

<details>
<summary>More screenshots</summary>

<div>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-2.png"><img src="images/screenshots/screenshot-desktop-2.png" alt="With the plugin: a folder of its own, beside the note" width="600"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-3.png"><img src="images/screenshots/screenshot-desktop-3.png" alt="And named after the note it belongs to, not the clock" width="600"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-4.png"><img src="images/screenshots/screenshot-desktop-4.png" alt="Rename the note and its attachments move with it" width="600"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-5.png"><img src="images/screenshots/screenshot-desktop-5.png" alt="The embed still resolves — nothing is left pointing nowhere" width="600"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-1.png"><img src="images/screenshots/screenshot-mobile-1.png" alt="Every pasted screenshot in one heap, named after the clock" width="270"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-2.png"><img src="images/screenshots/screenshot-mobile-2.png" alt="With the plugin: a folder of its own, beside the note" width="270"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-3.png"><img src="images/screenshots/screenshot-mobile-3.png" alt="And named after the note it belongs to, not the clock" width="270"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-4.png"><img src="images/screenshots/screenshot-mobile-4.png" alt="Rename the note and its attachments move with it" width="270"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-5.png"><img src="images/screenshots/screenshot-mobile-5.png" alt="The embed still resolves — nothing is left pointing nowhere" width="270"></a>
</div>

</details>

<!-- markdownlint-enable MD033 -->

## Demo vault

**The documentation is a demo vault.** Every feature has a note that explains what it does and why you would want it, and walks you through it with a file you supply.

**[Start reading here](<./demo-vault/00 Start.md>)** — it is plain markdown, so it works on GitHub with nothing installed.

A copy of the vault ships with every release. You can access it via any of the following:

1. Running the **Custom Attachment Location: Open demo vault** command.
2. Downloading `obsidian-custom-attachment-location-demo-vault.zip` from the [Releases](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases). It unzips into a single `obsidian-custom-attachment-location-demo-vault-<version>` folder.
3. Browsing its source in [`demo-vault/`](./demo-vault/README.md) in this repository.

## What it does

- **Choose the folder** each new attachment goes into, per note or per anything else a pattern can express — one folder beside every note, a folder per note, a folder per year. Or leave `shouldFollowObsidianAttachmentLocation` on, as a fresh install has it, and let Obsidian's own *Default location for new attachments* decide, keeping everything else this plugin does. Installing the plugin therefore moves nothing: attachments land where they always did until you switch that off and pick a pattern. While the plugin's pattern is in charge, Obsidian's own settings page says so instead of showing a value that is not in effect. [01 Attachment folder location](<./demo-vault/01 Attachment folder location.md>)
- **Choose the file name**, so an attachment is called something that says where it came from instead of `Pasted image 20250101120000`. [02 Attachment file naming](<./demo-vault/02 Attachment file naming.md>)
- **Patterns and tokens** — the vocabulary both of those are written in, including asking you for a value at paste time, reading one from the note's frontmatter, and defining your own tokens in JavaScript. [03 Tokens and patterns](<./demo-vault/03 Tokens and patterns.md>) · [04 Custom tokens](<./demo-vault/04 Custom tokens.md>) · [09 Token reference](<./demo-vault/09 Token reference.md>)
- **Catch attachments other plugins create** — some plugins write an attachment into the vault under a name of their own instead of asking Obsidian where it belongs. Set `renameAttachmentsCreatedByOtherPluginsMode` and those files are moved and renamed too, just after they appear — for every plugin, or only for the ones you name, or for every plugin except the ones you name. Off by default. [06 Settings](<./demo-vault/06 Settings.md>)
- **Collect attachments** — take the attachments a note already has and move them into the folder your settings say they belong in, for one note, one folder, or the whole vault. [05 Collect attachments](<./demo-vault/05 Collect attachments.md>)
- **Delete unused attachments** — move an attachment no note references any more to the trash, after a confirmation dialog. A folder you have designated as one attachment is judged whole: it goes only when nothing outside it references anything inside it, and otherwise stays intact. Set `orphanAttachmentScanMode` and the whole-vault sweep also reaches attachment folders whose note has been deleted, which nothing leads to any more. Off by default. [08 Delete unused attachments](<./demo-vault/08 Delete unused attachments.md>)
- **Keep it true over time** — attachments follow their note when it is renamed or moved, and can be deleted with it. Since 12.0.0 that half is done by [Advanced Rename and Delete Handler](https://obsidian.md/plugins?id=advanced-rename-and-delete-handler), which this plugin requires — it loads nothing without it, explains why, and installs it in one click — and hands its old settings to. Installing it changes nothing on its own: its defaults do nothing until you turn renames or deletions on. Two plugins handling one rename corrupt links and move attachments twice, so exactly one owns it. [06 Settings](<./demo-vault/06 Settings.md>)
- **Link display text** — give an inserted attachment link the attachment's own name as its text, which plugins that render captions can then use. [07 Link display text](<./demo-vault/07 Link display text.md>)
- **Jump between a note and its attachments** — reveal the folder a note's attachments are saved into, and go from an attachment back to the note that owns it. [10 Navigation](<./demo-vault/10 Navigation.md>)

## Tokens

Moved to [09 Token reference](<./demo-vault/09 Token reference.md>) — every token, its format schema and worked examples. For what a pattern is and the tokens most people use, start at [03 Tokens and patterns](<./demo-vault/03 Tokens and patterns.md>).

This heading stays so that the **See available tokens** links inside the plugin's own settings tab keep resolving, including from versions already installed.

### Custom tokens

Moved to [04 Custom tokens](<./demo-vault/04 Custom tokens.md>).

### Markdown URL format

Moved to [06 Settings](<./demo-vault/06 Settings.md>), under `markdownUrlFormat`.

## For plugin developers

Everything this plugin offers another plugin is declared in one hand-written file — [api.d.ts](./api.d.ts) at the repository root. It imports from `obsidian` and nothing else, so you can copy it into your own code or reference it where it sits, with no build-time dependency on this repository.

The API is published through the `obsidian-dev-utils` plugin registry under the plugin id `obsidian-custom-attachment-location`, so you get version negotiation, a handle that is revoked when this plugin unloads, and a wait that ends when it loads rather than a lookup that returns `undefined` because it ran first:

```ts
const apiRef = watchPluginApi<CustomAttachmentLocationApi>({
  apiVersionRange: '^1',
  app,
  component: this,
  pluginId: 'obsidian-custom-attachment-location'
});

const folder = await apiRef.value?.getAttachmentFolderPath({ notePath: 'Notes/Alpha.md' });
const properPath = await apiRef.value?.getProperAttachmentPath({ attachmentPathOrFile: 'image.png', notePath: 'Notes/Alpha.md' });
```

### Do not read `vault.getConfig('attachmentFolderPath')`

This plugin patches that call, which makes it look like the seam you want. It is not one. The patch answers with this plugin's value only while a note is open, and the value it answers with is **the open note's** — computed once when the file was opened. A plugin looping over every note in the vault therefore gets the active note's attachment folder for all of them, silently, with no error and nothing to distinguish it from a correct answer. The patch is a write-path override for Obsidian's own attachment creation, not a readable configuration.

`getAttachmentFolderPath` is the read, asked once per note. It answers `null` when this plugin leaves that note alone entirely, which is your cue to fall back to Obsidian's own `attachmentFolderPath` — a different answer from this plugin not being installed, and deliberately so.

Both reads arrived in contract version `1.0.0`, and both are asynchronous: an attachment folder is the result of evaluating a user-written template whose tokens can read the note's frontmatter and the attachment's bytes, so there is no synchronous answer to hand back. Neither ever asks the user anything, so a whole-vault audit raises no dialogs.

### Collecting a note's attachments

`collectAttachments`, added in contract version `1.2.0` (ask for `'^1.2.0'`), collects the attachments of the notes and folders you name, the way the `Collect attachments` commands do, without opening the note first:

```ts
await apiRef.value?.collectAttachments({ pathsOrFiles: ['Notes/Alpha.md'] });
```

It is an action, not a read, so it asks what the command asks: it confirms several files or a folder with the user, and it follows the user's settings for an attachment several notes share. The promise settles once the collect has finished, queued behind any collect already running. It replaces reaching into the plugin instance for `collectAttachmentsInAbstractFiles`, which still works but is superseded.

### Handing collect settings over

A plugin that used to collect attachments itself hands its settings over through `migrateSettings`, added in contract version `1.1.0`, so ask for `'^1.1.0'`. It proposes the values it held, and this plugin shows the user each one that would change next to the value it holds now. Nothing is written unless the user approves, and `isApplied: false` means they cancelled, so keep the proposal pending. `api.d.ts` lists the settings that can be proposed. The shape matches `obsidian-dev-utils`' `SettingsMigrationApi`, so its `SettingsMigrationComponent` can run the whole offer:

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

## Installation

The plugin is available in [the official Community Plugins repository](https://community.obsidian.md/plugins/obsidian-custom-attachment-location).

### Beta versions

To install the latest beta release of this plugin (regardless if it is available in [the official Community Plugins repository](https://community.obsidian.md) or not), follow these steps:

1. Ensure you have the [BRAT plugin](https://community.obsidian.md/plugins/obsidian42-brat) installed and enabled.
2. Click [Install via BRAT](https://intradeus.github.io/http-protocol-redirector?r=obsidian://brat?plugin=https://github.com/mnaoumov/obsidian-custom-attachment-location).
3. An Obsidian pop-up window should appear. In the window, click the `Add plugin` button once and wait a few seconds for the plugin to install.

## Debugging

By default, debug messages for this plugin are hidden.

To show them, run the following command in the `DevTools Console`:

```js
window.DEBUG.enable('obsidian-custom-attachment-location');
```

For more details, refer to the [documentation](https://mnaoumov.dev/obsidian-dev-utils/guides/debugging/).

## Attributions

[In Oct 2021](https://github.com/RainCat1998/obsidian-custom-attachment-location/commit/1c92b85f7a5eba71cf54e20452eb8f3c2404a273), the plugin was created by [RainCat1998](https://github.com/RainCat1998).

[From July 2024](https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/59), the plugin is maintained by [Michael Naumov](https://github.com/mnaoumov/).

From December 2025, the project repository is hosted at [mnaoumov/obsidian-custom-attachment-location](https://github.com/mnaoumov/obsidian-custom-attachment-location).

The original author's repository is preserved as an archive of issues/PRs/discussions/releases at [RainCat1998/obsidian-custom-attachment-location](https://github.com/RainCat1998/obsidian-custom-attachment-location).

## Changelog

All notable changes to this project will be documented in the [CHANGELOG](./CHANGELOG.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING](./CONTRIBUTING.md) to get set up.

## Support

<!-- markdownlint-disable MD033 -->

<a href="https://www.buymeacoffee.com/mnaoumov" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="60" width="217"></a>

<!-- markdownlint-enable MD033 -->

## My other Obsidian resources

[See my other Obsidian resources](https://github.com/mnaoumov/obsidian-resources).

## License

Copyright (c) [RainCat1998](https://github.com/RainCat1998), [Michael Naumov](https://github.com/mnaoumov/).
