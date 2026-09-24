/**
 * @file
 *
 * Everything this plugin knows about Consistent Attachments and Links, which still ships its own copy of
 * the attachment-collecting commands this plugin owns.
 *
 * Both plugins register `collect-attachments-entire-vault`, `collect-attachments-in-current-folder`,
 * `collect-attachments-in-file` and `move-attachment-to-proper-folder`, under the same English names.
 * Obsidian namespaces command ids per plugin, so nothing fails to register — the user simply sees each
 * command twice, with nothing but the plugin name to tell the copies apart, and running either one does
 * the work twice.
 *
 * That is annoying rather than destructive, so this is declared as a WARNING and both plugins keep
 * running. Refusing to load over a duplicated palette entry would cost the user far more than the
 * duplicate does.
 */

/**
 * The versions of that plugin whose collecting commands overlap with this plugin's.
 *
 * A range, not a minimum, and closed at that plugin's next major on purpose: dropping a user-facing
 * command is a breaking change for it, so the release that gives collecting up cannot be a minor. Nothing
 * below `5.0.0` has shipped that removal yet, which is why every released version conflicts today.
 *
 * `5.0.0` is also the release that hands its collect settings over through this plugin's `migrateSettings`, so
 * from that version on the two plugins never both collect: the older one warns here, the newer one has
 * stopped.
 *
 * TODO: pin this to the real version once that release exists, and delete the declaration outright once
 * every version that still collects is old enough to have aged out.
 */
export const CONSISTENT_ATTACHMENTS_AND_LINKS_COLLECTING_VERSION_RANGE = '<5.0.0';

/**
 * The plugin id, as listed in Obsidian's community plugin registry.
 *
 * Note that it carries no `obsidian-` prefix, unlike this plugin's own id.
 */
export const CONSISTENT_ATTACHMENTS_AND_LINKS_PLUGIN_ID = 'consistent-attachments-and-links';

/**
 * The display name, used when telling the user which plugin the commands are duplicated with.
 */
export const CONSISTENT_ATTACHMENTS_AND_LINKS_PLUGIN_NAME = 'Consistent Attachments and Links';
