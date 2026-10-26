# Custom Attachment Location

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/mnaoumov) [![GitHub release](https://img.shields.io/github/v/release/mnaoumov/obsidian-custom-attachment-location)](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases) [![GitHub downloads](https://img.shields.io/github/downloads/mnaoumov/obsidian-custom-attachment-location/total)](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases) [![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/mnaoumov/obsidian-custom-attachment-location)

Paste a screenshot into [Obsidian](https://obsidian.md/) and it lands in one shared folder as `Pasted image 20250101120000`. A year later that folder holds a thousand files whose names say nothing about which note they belong to.

This plugin decides **where** each attachment is stored and **what** it is called, from a pattern of tokens such as `{{noteFileName}}` and `{{date:{momentJsFormat:'YYYYMMDD'}}}`. Keeping that true as notes are renamed, moved and deleted is the job of its companion, [Advanced Rename and Delete Handler](https://obsidian.md/plugins?id=advanced-rename-and-delete-handler), which this plugin requires and installs for you in one click.

<!-- markdownlint-disable MD033 -->

<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-1.png"><img src="images/screenshots/screenshot-desktop-1.png" alt="Every pasted screenshot in one heap, named by the clock" width="600"></a>

<details>
<summary>More screenshots</summary>

<div>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-2.png"><img src="images/screenshots/screenshot-desktop-2.png" alt="With the plugin: a folder of its own, beside the note" width="600"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-3.png"><img src="images/screenshots/screenshot-desktop-3.png" alt="And named after the note it belongs to, not the clock" width="600"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-4.png"><img src="images/screenshots/screenshot-desktop-4.png" alt="Rename the note and its attachments move with it" width="600"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-desktop-5.png"><img src="images/screenshots/screenshot-desktop-5.png" alt="The embed still resolves — no broken links" width="600"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-1.png"><img src="images/screenshots/screenshot-mobile-1.png" alt="Every pasted screenshot in one heap, named by the clock" width="270"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-2.png"><img src="images/screenshots/screenshot-mobile-2.png" alt="With the plugin: a folder of its own, beside the note" width="270"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-3.png"><img src="images/screenshots/screenshot-mobile-3.png" alt="And named after the note it belongs to, not the clock" width="270"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-4.png"><img src="images/screenshots/screenshot-mobile-4.png" alt="Rename the note and its attachments move with it" width="270"></a>
<a href="https://github.com/mnaoumov/obsidian-custom-attachment-location/blob/HEAD/images/screenshots/screenshot-mobile-5.png"><img src="images/screenshots/screenshot-mobile-5.png" alt="The embed still resolves — no broken links" width="270"></a>
</div>

</details>

<!-- markdownlint-enable MD033 -->

## Demo vault

**The documentation is a demo vault.** Every feature has a note that explains what it does and why you would want it, and walks you through it with a file you supply.

**[Start reading here](<./demo-vault/00 Start.md>)** — it is plain markdown, so it works on GitHub with nothing installed.

A copy of the vault ships with every release. You can access it via any of the following:

1. Running the **`Custom Attachment Location`: Open demo vault** command.
2. Downloading `obsidian-custom-attachment-location-demo-vault.zip` from the [Releases](https://github.com/mnaoumov/obsidian-custom-attachment-location/releases). It unzips into a single `obsidian-custom-attachment-location-demo-vault-<version>` folder.
3. Browsing its source in [`demo-vault/`](./demo-vault/README.md) in this repository.

## What it does

- **Choose the folder** each new attachment goes into, from a pattern: beside the note, a folder per note, a folder per year. A fresh install follows Obsidian's own setting until you pick a pattern. [01 Attachment folder location](<./demo-vault/01 Attachment folder location.md>)
- **Choose the file name**, so an attachment says where it came from; by default only pasted images are renamed. [02 Attachment file naming](<./demo-vault/02 Attachment file naming.md>)
- **Patterns and tokens**, the vocabulary both are written in, including prompting at paste time, reading frontmatter and your own JavaScript tokens. [03 Tokens and patterns](<./demo-vault/03 Tokens and patterns.md>) · [04 Custom tokens](<./demo-vault/04 Custom tokens.md>) · [09 Token reference](<./demo-vault/09 Token reference.md>)
- **Catch attachments other plugins create**, such as an image pasted into an `Excalidraw` drawing, and move and rename them too. [06 Settings](<./demo-vault/06 Settings.md>)
- **Collect attachments** a note already has into the folder your settings say, for a note, a folder or the whole vault, optionally merging identical files. [05 Collect attachments](<./demo-vault/05 Collect attachments.md>)
- **Delete unused attachments**, after a confirmation, optionally including folders whose note is gone. [08 Delete unused attachments](<./demo-vault/08 Delete unused attachments.md>)
- **Keep it true over time**: attachments follow their note on rename, move and delete, through `Advanced Rename and Delete Handler`. [06 Settings](<./demo-vault/06 Settings.md>)
- **Link display text**: give an inserted link the attachment's own name as its text. [07 Link display text](<./demo-vault/07 Link display text.md>)
- **Jump between a note and its attachments**, both ways. [10 Navigation](<./demo-vault/10 Navigation.md>)

## Tokens

Moved to [09 Token reference](<./demo-vault/09 Token reference.md>). For what a pattern is, start at [03 Tokens and patterns](<./demo-vault/03 Tokens and patterns.md>).

### Custom tokens

Moved to [04 Custom tokens](<./demo-vault/04 Custom tokens.md>).

### Markdown URL format

Moved to [06 Settings](<./demo-vault/06 Settings.md>), under `markdownUrlFormat`.

## Similar plugins

- [`Attachment Management`](https://community.obsidian.md/plugins/attachment-management) — the closest in scope: attachment path and name patterns, a command that rearranges existing attachments, and renaming attachments when their note is renamed, all in one plugin; this plugin leaves following note renames and moves to `Advanced Rename and Delete Handler`.
- [`Attachment Manager`](https://community.obsidian.md/plugins/attachment-manager) — binds one attachment folder to each note's name, renaming, deleting and showing or hiding it with the note; this plugin builds the folder from a pattern, so one folder per note is one layout among many.
- [`Attachment Location Manager`](https://community.obsidian.md/plugins/attachment-location-manager) — sets the attachment location globally, per folder or per note, resolved by nearest match with per-extension exceptions; this plugin uses one pattern whose tokens can read the note's path and frontmatter.
- [`Attachment Placement`](https://community.obsidian.md/plugins/attachment-placement) — places new attachments by rules about where they are used or added; it decides the folder, while this plugin decides the file name as well.
- [`Attachment Steward`](https://community.obsidian.md/plugins/attachment-steward) — organizes attachments into templated folders and file names, keeps the original file name, and catches bulk imports as they land; this plugin also collects existing attachments and deletes unused ones on demand.
- [`Note Companion Folder`](https://community.obsidian.md/plugins/note-companion-folder) — manages a separate attachment folder for each note; this plugin can produce that layout from a pattern, alongside other layouts.
- [`Foldwise`](https://community.obsidian.md/plugins/foldwise) — routes pasted files into per-folder asset folders by rules and manages saved assets on one page; this plugin routes by a token pattern and has no assets page.
- [`Attachment Renamer`](https://community.obsidian.md/plugins/attachment-renamer) — renames pasted, dropped and existing attachments with a template; it names the file, while this plugin chooses the folder too.
- [`Paste image rename`](https://community.obsidian.md/plugins/obsidian-paste-image-rename) — renames an image after it is pasted, by a name pattern or by asking; it names the file and leaves the folder to Obsidian.
- [`Image Renamer`](https://community.obsidian.md/plugins/image-renamer) — renames pasted images with templates that can read frontmatter, and can set a per-note image folder from a frontmatter key; it handles images, while this plugin handles every attachment type.
- [`Unique attachments`](https://community.obsidian.md/plugins/unique-attachments) — renames attachments to names derived from a hash of their content; this plugin can name by content hash too, through `{{attachmentFileHash}}` in a pattern, and chooses the folder as well.
- [`Consistent Attachments and Links`](https://community.obsidian.md/plugins/consistent-attachments-and-links) — moves a note's attachments with it and keeps links consistent across the vault; it focuses on link consistency, while this plugin decides where new attachments go and what they are called.

Last searched for similar plugins on 2026-10-26.

## For plugin developers

This plugin publishes an API another plugin can call: attachment folder and path reads, a collect action, its full path resolver and a collect-settings handover. It is declared in [api.d.ts](./api.d.ts), with its contract in [api-contract.ts](./api-contract.ts). [Plugin API](./docs/plugin-api.md) explains how to reach it, with or without `@mnaoumov/obsidian-lib`, and why `vault.getConfig('attachmentFolderPath')` is not a seam to read.

## Installation

The plugin is available in [the official Community Plugins repository](https://community.obsidian.md/plugins/obsidian-custom-attachment-location).

### Beta versions

To install the latest beta release of this plugin (regardless if it is available in [the official Community Plugins repository](https://community.obsidian.md) or not), follow these steps:

1. Ensure you have the [BRAT plugin](https://community.obsidian.md/plugins/obsidian42-brat) installed and enabled.
2. Click [Install via BRAT](https://intradeus.github.io/http-protocol-redirector?r=obsidian://brat?plugin=https://github.com/mnaoumov/obsidian-custom-attachment-location).
3. An Obsidian pop-up window should appear. In the window, click the `Add plugin` button once and wait a few seconds for the plugin to install.

## Debugging

By default, debug messages for this plugin (id: `obsidian-custom-attachment-location`) are hidden.

If you need to enable them refer to the [documentation](https://mnaoumov.dev/obsidian-lib/guides/debugging/).

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
