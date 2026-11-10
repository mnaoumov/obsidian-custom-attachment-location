# Original name storage

`Custom Attachment Location` remembers attachment arrival names so `{{originalAttachmentFileName}}` stays stable after a rename or collect. This is durable history, not a disposable cache. New installations keep it locally in IndexedDB and create no vault transport folder. Existing device replicas keep their previous Markdown synchronization until explicit setup approves JSON. Update every participating device and configure its provider before switching; older clients cannot read JSON. A new device must opt in even if the plugin settings arrive through sync.

Open **Settings → `Custom Attachment Location` → Original name storage** to configure this device. Disabling synchronization keeps local names, corrections and causal history; it never deletes existing shared files. Local history belongs to this device's vault identity. Clearing Obsidian's local application data can remove it; enable file synchronization if you need another copy.

## When synchronization is worth turning on

Synchronize original names only when both of these hold:

1. Another device uses this vault, through Obsidian Sync or another sync tool.
2. A template reads `{{originalAttachmentFileName}}`: an attachment folder or file name, a collected or renamed file name, the inserted link text, the Markdown URL format, or a custom token.

Without the first, nobody else needs the names. Without the second, no template reads them, so nothing is computed differently on another device. On a single device, local history already keeps `{{originalAttachmentFileName}}` stable.

The **Original name storage** page applies this to the device you are on and shows one line of advice:

| This device | Advice |
| --- | --- |
| Obsidian Sync is off, or on without a remote vault | Names stay here and no folder is created. Use **Set up external sync** only if another tool carries the vault and a template reads the name. |
| Obsidian Sync is connected, and a template reads the name | Recommended: choose **Set up Obsidian Sync**. |
| Obsidian Sync is connected, and no template reads the name | Not needed yet. |
| Set up for Obsidian Sync, which is no longer connected here | Nothing reaches other devices. Reconnect Obsidian Sync, or disable sync on this device. |

The plugin cannot see Git, Syncthing, iCloud or a WebDAV client, so it never assumes they are absent: **Set up external sync** is always available. It never turns synchronization on by itself, and a device that synchronized under an earlier version keeps doing so until you disable it.

## Enable synchronization

Choose **Set up Obsidian Sync** or **Set up external sync** and complete the confirmation checklist. Consent is local to each device and does not travel in `data.json`. The first device can join without waiting for another participant.

For Obsidian Sync, the plugin checks this device first. **Set up Obsidian Sync** refuses when Obsidian Sync is not connected to a remote vault, or when Sync's own settings would skip a history location: the history is JSON, so it needs **Sync all other types**, and no history location may be in Sync's **Excluded folders**. The message names the location. Every other participating device needs the same settings: connect the same remote vault, enable **Sync all other types**, restart Obsidian after changing Sync settings, and run the setup there too. The plugin does not change Sync settings and cannot check other devices. Arbitrary hidden folders are excluded, including arbitrary plugin data under `.obsidian`; the special configuration-folder sync mechanism does not promise to carry these files. See [Obsidian Sync settings](https://help.obsidian.md/sync/settings).

For Git, WebDAV or another external provider, explicitly include JSON files and every history location listed in settings, on every participating device. Hidden folders need support and configuration in that provider. Excluding a folder from Obsidian search is separate from excluding it from synchronization.

## The synchronized folder

When this device first turns synchronization on, the history goes into `@Plugin sync data (DO NOT REMOVE)` at the root of the vault. A device or vault that already synchronized with an earlier version keeps using `Plugin data`, the folder those versions used, so devices on one vault never split their history between two folders. Use **Apply folder** below to move it.

Each folder that holds history gets a `README.md` saying what it is for. The plugin rewrites that file whenever its text differs, so edits to it do not last.

The plugin also lists each such folder, and the **Plugin data folder** while synchronization is on, in **Settings → Files and links → Excluded files**, so the history stays out of search, the graph and the quick switcher. When the folder changes, the plugin replaces only the entry it added itself. An entry you added yourself is never removed. A hidden folder gets no entry, because Obsidian never indexes it.

Do not delete the folder or anything in it while any device synchronizes, and do not rename or move anything inside it. It is history, not a cache, and what is removed cannot be rebuilt. To get rid of it for good, see [Stop synchronizing and remove the folders](#stop-synchronizing-and-remove-the-folders).

### Moving the whole folder

You can move or rename the folder as a whole, or a folder above it, for example from `Plugin data` to `99-Meta/Plugin data`. Do it in Obsidian's file explorer, or with any tool while Obsidian is closed. Before it next writes history, each device checks that the history is still where it left it. If it is gone, and exactly one other folder of the vault holds this plugin's `obsidian-custom-attachment-location/original-attachment-names-v1` history, the device follows it there instead of recreating the old folder. A device added later finds it the same way. Folders whose name starts with a dot are not searched.

- **Exactly one copy.** If the history is found in more than one folder, for example because the old folder was recreated before the move reached a device, nothing is followed. Delete the copy that holds only a stray `devices` file once you have checked that the other holds the full history.
- **Stores set up for JSON cannot follow a move yet.** Setting up synchronization in this version, and **Apply folder**, record a switch in `locations-v1`, and those records name the folder they were written in. This version cannot follow a moved folder that holds such records. Instead of starting a second, split history at the old place, the device pauses synchronization, keeps recording names locally, and says so. Move the folder back to resume. For such a history, use **Apply folder** to change where new history is written; it keeps the original folder as the anchor. A history kept in legacy Markdown, as earlier versions wrote it, has no such records and follows a move.

## Change the folder

**Plugin data folder** is a static vault-relative parent, defaulting to `@Plugin sync data (DO NOT REMOVE)`. For example, use `99-Meta/Plugin sync data`. Enable **Allow hidden plugin data folders** to use a destination such as `99-Meta/.plugin-data` with an external sync provider. Paths cannot contain tokens, absolute paths, traversal or backslashes.

Save the destination, complete synchronization setup on this device, then choose **Apply folder**. Merely receiving a settings file never relocates the writer.

**Apply folder copies; it does not move.** The original folder stays in the vault for good, next to the new one, because every device opens it first to find where the history went. So applying a folder to get `Plugin data` out of sight leaves two folders, not one. To keep the vault tidy, move the whole folder instead while that still works ([Moving the whole folder](#moving-the-whole-folder)), or keep the history out of search with **Excluded files**, which the plugin already does. To be rid of every folder, see [Stop synchronizing and remove the folders](#stop-synchronizing-and-remove-the-folders).

Choose **Apply folder** on one device only. It records the move in the original folder's `locations-v1` records. Every device that has synchronization set up re-reads those records each time it merges history, and it switches to the new folder by itself once its sync tool delivers the record. Applying the same path again on another device is harmless but unnecessary. A different path applied on a device that has not yet received the first move conflicts with that move and fails closed. The plugin copies and verifies only its own `obsidian-custom-attachment-location/original-attachment-names-v1` subtree through the shared library. Sibling plugins' data is untouched. A conflicting occupied file refuses the transition; byte-identical retries are safe. If interrupted, restore file delivery and apply the same destination again. Do not overwrite conflicting histories to force it through. Attempted destinations remain excluded from attachment lifecycle events even after a disabled restart.

History locations are retained, including the original `obsidian-custom-attachment-location/original-attachment-names-v1` discovery anchor under the folder this device first synchronized in, and its `locations-v1` records. Keep ALL listed roots synchronized permanently. Relocation changes where new records are written; it does not promise to remove the original top-level folder. Never delete the original folder after a move while any device still synchronizes, even once every device has switched: it is the anchor every device, including one added later, opens first to find where the history went. Disabling synchronization stops transport I/O but does not remove files. There is no automatic old-root cleanup or arbitrary relocation back to a previously used root.

Update the plugin on every participating device before relocating. Offline devices can deliver late records to retained roots, which upgraded devices continue merging. Older clients do not understand the relocation protocol; retire or upgrade them rather than deleting their history. New documents use JSON to stay outside ordinary Markdown note indexing. Legacy Markdown is read and retained during migration, and can remain indexed until you exclude it from search. Do not rename or move individual transport files manually; moving the whole folder is covered in [Moving the whole folder](#moving-the-whole-folder).

## Stop synchronizing and remove the folders

The history folders exist only for synchronization. To remove them for good:

1. On **every** device that uses the vault, open **Original name storage** and choose **Disable sync on this device**. A device that still synchronizes recreates the folder the next time it writes history, so do this everywhere first, including devices that are offline today.
2. Let your sync tool settle, then delete every folder listed under **History locations**: the original folder and every folder **Apply folder** moved the history to. Delete them on one device; the sync tool carries the deletion to the others.

What stays and what is lost:

- Each device keeps every original name it already knows, in its own local history, and keeps recording new ones. On a single device nothing changes.
- Devices stop sharing names. A template that reads `{{originalAttachmentFileName}}` then gives an attachment's original name only on the device that saw it arrive. Another device uses the name it knows, or falls back to the current name with a warning, so the same collect or rename can produce different names on different devices.
- A device added to the vault later starts with no history from the others.

The next time Obsidian starts, the plugin removes the **Excluded files** entries it added for the folders that are gone. You can set synchronization up again at any time; it starts a new shared history from what each device has kept locally.

## Recovery

Names captured while synchronization is disabled remain in the same local causal store and are merged when you enable it again. The legacy `original-attachment-names.json` remains untouched as recovery input. Original source paths are not recorded. A broken or incomplete transition fails closed so it cannot silently start a new independent writer: finish synchronization or restore the conflicting files from backup before retrying. Keep the original anchor, device logs and snapshots together; current attachment names alone cannot reconstruct their history.
