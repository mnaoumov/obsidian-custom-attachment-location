# Original name storage

`Custom Attachment Location` remembers attachment arrival names so `{{originalAttachmentFileName}}` stays stable after a rename or collect. This is durable history, not a disposable cache. New installations keep it locally in IndexedDB and create no vault transport folder. Existing device replicas keep their previous Markdown synchronization until explicit setup approves JSON. Update every participating device and configure its provider before switching; older clients cannot read JSON. A new device must opt in even if the plugin settings arrive through sync.

Open **Settings → `Custom Attachment Location` → Original name storage** to configure this device. Disabling synchronization keeps local names, corrections and causal history; it never deletes existing shared files. Local history belongs to this device's vault identity. Clearing Obsidian's local application data can remove it; enable file synchronization if you need another copy.

## Enable synchronization

Choose **Set up Obsidian Sync** or **Set up external sync** and complete the confirmation checklist. Consent is local to each device and does not travel in `data.json`. The first device can join without waiting for another participant.

For Obsidian Sync, connect the vault to its remote vault and enable **Sync all other types** on every participating device. Restart Obsidian after changing Sync settings. The setup is a manual verification checklist: the plugin does not change Sync settings or claim that remote devices are ready. Arbitrary hidden folders are excluded, including arbitrary plugin data under `.obsidian`; the special configuration-folder sync mechanism does not promise to carry these files. See [Obsidian Sync settings](https://help.obsidian.md/sync/settings).

For Git, WebDAV or another external provider, explicitly include JSON files and every history location listed in settings, on every participating device. Hidden folders need support and configuration in that provider. Excluding a folder from Obsidian search is separate from excluding it from synchronization.

## The synchronized folder

When this device first turns synchronization on, the history goes into `@Plugin sync data (DO NOT REMOVE)` at the root of the vault. A device or vault that already synchronized with an earlier version keeps using `Plugin data`, the folder those versions used, so devices on one vault never split their history between two folders. Use **Apply folder** below to move it.

Each folder that holds history gets a `README.md` saying what it is for. The plugin rewrites that file whenever its text differs, so edits to it do not last.

The plugin also lists each such folder, and the **Plugin data folder** while synchronization is on, in **Settings → Files and links → Excluded files**, so the history stays out of search, the graph and the quick switcher. When the folder changes, the plugin replaces only the entry it added itself. An entry you added yourself is never removed. A hidden folder gets no entry, because Obsidian never indexes it.

Do not delete, move or rename the folder or anything in it. It is history, not a cache, and what is removed cannot be rebuilt.

## Change the folder

**Plugin data folder** is a static vault-relative parent, defaulting to `@Plugin sync data (DO NOT REMOVE)`. For example, use `99-Meta/Plugin sync data`. Enable **Allow hidden plugin data folders** to use a destination such as `99-Meta/.plugin-data` with an external sync provider. Paths cannot contain tokens, absolute paths, traversal or backslashes.

Save the destination, complete synchronization setup on this device, then choose **Apply folder**. Merely receiving a settings file never relocates the writer. The plugin copies and verifies only its own `obsidian-custom-attachment-location/original-attachment-names-v1` subtree through the shared library. Sibling plugins' data is untouched. A conflicting occupied file refuses the transition; byte-identical retries are safe. If interrupted, restore file delivery and apply the same destination again. Do not overwrite conflicting histories to force it through. Attempted destinations remain excluded from attachment lifecycle events even after a disabled restart.

History locations are retained, including the original `obsidian-custom-attachment-location/original-attachment-names-v1` discovery anchor under the folder this device first synchronized in, and its `locations-v1` records. Keep ALL listed roots synchronized permanently. Relocation changes where new records are written; it does not promise to remove the original top-level folder. Disabling synchronization stops transport I/O but does not remove files. There is no automatic old-root cleanup or arbitrary relocation back to a previously used root.

Update the plugin on every participating device before relocating. Offline devices can deliver late records to retained roots, which upgraded devices continue merging. Older clients do not understand the relocation protocol; retire or upgrade them rather than deleting their history. New documents use JSON to stay outside ordinary Markdown note indexing. Legacy Markdown is read and retained during migration, and can remain indexed until you exclude it from search. Do not rename or move transport files manually.

## Recovery

Names captured while synchronization is disabled remain in the same local causal store and are merged when you enable it again. The legacy `original-attachment-names.json` remains untouched as recovery input. Original source paths are not recorded. A broken or incomplete transition fails closed so it cannot silently start a new independent writer: finish synchronization or restore the conflicting files from backup before retrying. Keep the original anchor, device logs and snapshots together; current attachment names alone cannot reconstruct their history.
