/**
 * @file
 *
 * The runtime half of this plugin's published contract: the registry contract and its version.
 *
 * The TYPES are not declared here. They live in the repo-root `api.d.ts`, which is the file a consumer
 * reads, and are re-exported from it so there is exactly one declaration of each and nothing to drift.
 */

import type { PluginApiContract } from 'obsidian-dev-utils/obsidian/plugin/plugin-api';

export type {
  CollectAttachmentsParams,
  CollectAttachmentUsedByMultipleNotesMode,
  CustomAttachmentLocationApi,
  GetAttachmentFolderPathParams,
  GetProperAttachmentPathParams,
  MigratableCollectSettings,
  MigrateSettingsParams,
  MigrateSettingsResult,
  MoveAttachmentToProperFolderUsedByMultipleNotesMode
} from '../api.d.ts';

/**
 * The contract this plugin publishes. It declares the method names; a consumer that wants schema validation
 * at the boundary supplies its own contract to `watchPluginApi`, and the consumer's wins.
 */
export const PLUGIN_API_CONTRACT: PluginApiContract = {
  collectAttachments: {},
  getAttachmentFolderPath: {},
  getProperAttachmentPath: {},
  migrateSettings: {}
};

/**
 * The version of the contract above — independent of the plugin's own version, so a consumer asks for `'^1'`
 * and keeps working across releases that change nothing it depends on.
 *
 * `1.0.0` is the pair of per-note reads. `1.1.0` adds `migrateSettings`, which receives the collect settings
 * Consistent Attachments and Links hands over when it stops collecting. That is purely additive, so a consumer
 * of the reads keeps asking for `'^1'`, and a consumer of the migration asks for `'^1.1.0'`. `1.2.0` adds
 * `collectAttachments`, the declared replacement for the plugin instance's `collectAttachmentsInAbstractFiles`,
 * so a consumer of it asks for `'^1.2.0'`.
 */
export const PLUGIN_API_VERSION = '1.2.0';
