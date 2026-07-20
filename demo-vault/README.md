# Custom Attachment Location demo vault

A small Obsidian vault that demonstrates the [Custom Attachment Location](https://github.com/mnaoumov/obsidian-custom-attachment-location) plugin - it lets you choose where each attachment is saved and how it is named, using tokens like `${noteFileName}` and `${date:{momentJsFormat:'YYYYMMDD'}}`.

Open [00 Start](<./00 Start.md>) and work through the numbered notes. Paste or drag an image into [01 Attachment folder location](<./01 Attachment folder location.md>) and watch it land in a per-note folder, then explore naming, tokens, custom tokens, and the **Collect attachments** commands. You supply the files - the plugin decides where they go and what they are called.

## First open

The first time you open this vault, Obsidian treats it as **untrusted**, so the bundled plugins are listed but not loaded until you **Trust author and enable plugins** and reload. After that, the Demo Vault Helper installs [CodeScript Toolkit](https://github.com/mnaoumov/obsidian-codescript-toolkit) and opens the start note for you.
