# Custom Attachment Location

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/mnaoumov)
[![GitHub release](https://img.shields.io/github/v/release/mnaoumov/obsidian-custom-attachment-location)](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/mnaoumov/obsidian-custom-attachment-location/total)](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/mnaoumov/obsidian-custom-attachment-location)

Paste a screenshot into [Obsidian](https://obsidian.md/) and it lands in one shared attachment folder
under a name like `Pasted image 20250101120000`. A year later that folder holds a thousand files whose
names say nothing about which note they belong to, and moving or renaming a note leaves its attachments
behind. This plugin lets you decide **where** each attachment is stored and **what** it is called, from
a pattern built out of tokens — `${noteFileName}`, `${date:{momentJsFormat:'YYYYMMDD'}}`, and about
twenty more — and then keeps that arrangement true as notes are renamed, moved and deleted.

<!-- markdownlint-disable MD033 -->

<a href="images/screenshots/screenshot-desktop-1.png"><img src="images/screenshots/screenshot-desktop-1.png" alt="Every pasted screenshot in one heap, named after the clock" width="600"></a>

<details>
<summary>More screenshots</summary>

<a href="images/screenshots/screenshot-desktop-2.png"><img src="images/screenshots/screenshot-desktop-2.png" alt="With the plugin: a folder of its own, beside the note" width="600"></a>
<a href="images/screenshots/screenshot-desktop-3.png"><img src="images/screenshots/screenshot-desktop-3.png" alt="And named after the note it belongs to, not the clock" width="600"></a>
<a href="images/screenshots/screenshot-desktop-4.png"><img src="images/screenshots/screenshot-desktop-4.png" alt="Rename the note and its attachments move with it" width="600"></a>
<a href="images/screenshots/screenshot-desktop-5.png"><img src="images/screenshots/screenshot-desktop-5.png" alt="The embed still resolves — nothing is left pointing nowhere" width="600"></a>
<a href="images/screenshots/screenshot-mobile-1.png"><img src="images/screenshots/screenshot-mobile-1.png" alt="Every pasted screenshot in one heap, named after the clock" width="270"></a>
<a href="images/screenshots/screenshot-mobile-2.png"><img src="images/screenshots/screenshot-mobile-2.png" alt="With the plugin: a folder of its own, beside the note" width="270"></a>
<a href="images/screenshots/screenshot-mobile-3.png"><img src="images/screenshots/screenshot-mobile-3.png" alt="And named after the note it belongs to, not the clock" width="270"></a>
<a href="images/screenshots/screenshot-mobile-4.png"><img src="images/screenshots/screenshot-mobile-4.png" alt="Rename the note and its attachments move with it" width="270"></a>
<a href="images/screenshots/screenshot-mobile-5.png"><img src="images/screenshots/screenshot-mobile-5.png" alt="The embed still resolves — nothing is left pointing nowhere" width="270"></a>

</details>

<!-- markdownlint-enable MD033 -->

## Demo vault

**The documentation is a demo vault.** Every feature has a note that explains what it does and why you
would want it, and walks you through it with a file you supply.

**[Start reading here](<./demo-vault/00 Start.md>)** — it is plain markdown, so it works on GitHub with
nothing installed.

A copy of the vault ships with every release. You can access it via any of the following:

1. Running the **Custom Attachment Location: Open demo vault** command.
2. Downloading `obsidian-custom-attachment-location-demo-vault-<version>.zip` (`<version>` is the release version) from the [Releases](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases).
3. Browsing its source in [`demo-vault/`](./demo-vault/README.md) in this repository.

## What it does

- **Choose the folder** each new attachment goes into, per note or per anything else a pattern can
  express — one folder beside every note, a folder per note, a folder per year.
  [01 Attachment folder location](<./demo-vault/01 Attachment folder location.md>)
- **Choose the file name**, so an attachment is called something that says where it came from instead
  of `Pasted image 20250101120000`.
  [02 Attachment file naming](<./demo-vault/02 Attachment file naming.md>)
- **Patterns and tokens** — the vocabulary both of those are written in, including asking you for a
  value at paste time, reading one from the note's frontmatter, and defining your own tokens in
  JavaScript.
  [03 Tokens and patterns](<./demo-vault/03 Tokens and patterns.md>) ·
  [04 Custom tokens](<./demo-vault/04 Custom tokens.md>) ·
  [09 Token reference](<./demo-vault/09 Token reference.md>)
- **Catch attachments other plugins create** — some plugins write an attachment into the vault under a
  name of their own instead of asking Obsidian where it belongs. Turn on
  `shouldRenameAttachmentsCreatedByOtherPlugins` and those files are moved and renamed too, just after
  they appear. Off by default.
  [06 Settings](<./demo-vault/06 Settings.md>)
- **Collect attachments** — take the attachments a note already has and move them into the folder your
  settings say they belong in, for one note, one folder, or the whole vault.
  [05 Collect attachments](<./demo-vault/05 Collect attachments.md>)
- **Delete unused attachments** — move an attachment no note references any more to the trash, after a
  confirmation dialog.
  [08 Delete unused attachments](<./demo-vault/08 Delete unused attachments.md>)
- **Keep it true over time** — attachments follow their note when it is renamed or moved, and can be
  deleted with it.
  [06 Settings](<./demo-vault/06 Settings.md>)
- **Link display text** — give an inserted attachment link the attachment's own name as its text, which
  plugins that render captions can then use.
  [07 Link display text](<./demo-vault/07 Link display text.md>)

## Tokens

Moved to [09 Token reference](<./demo-vault/09 Token reference.md>) — every token, its format schema
and worked examples. For what a pattern is and the tokens most people use, start at
[03 Tokens and patterns](<./demo-vault/03 Tokens and patterns.md>).

This heading stays so that the **See available tokens** links inside the plugin's own settings tab keep
resolving, including from versions already installed.

### Custom tokens

Moved to [04 Custom tokens](<./demo-vault/04 Custom tokens.md>).

### Markdown URL format

Moved to [06 Settings](<./demo-vault/06 Settings.md>), under `markdownUrlFormat`.

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
