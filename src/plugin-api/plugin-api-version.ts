/**
 * @file
 *
 * The version of this plugin's published contract, kept apart from `./plugin-api.ts` so code that runs outside
 * Obsidian (an integration suite's Node side) can read it without loading the contract, which imports `obsidian`.
 */

/**
 * The version of the contract in the repo-root `api-contract.ts` — independent of the plugin's own version, so a
 * consumer asks for `'^1'` and keeps working across releases that change nothing it depends on.
 *
 * `1.0.0` is the pair of per-note reads. `1.1.0` adds `migrateSettings`, which receives the collect settings
 * `Consistent Attachments and Links` hands over when it stops collecting. That is purely additive, so a consumer
 * of the reads keeps asking for `'^1'`, and a consumer of the migration asks for `'^1.1.0'`. `1.2.0` adds
 * `collectAttachments`, the declared replacement for the plugin instance's `collectAttachmentsInAbstractFiles`,
 * so a consumer of it asks for `'^1.2.0'`. `1.3.0` adds `getAvailablePathForAttachments` and
 * `isAttachmentUnitFolder`, the attachment-path policy a library used to read off members grafted onto
 * `Vault.getAvailablePathForAttachments`, so a consumer of them asks for `'^1.3.0'`.
 */
export const PLUGIN_API_VERSION = '1.3.0';
