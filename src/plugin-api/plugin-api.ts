/**
 * @file
 *
 * The runtime half of this plugin's published contract: the registry contract and its version. The contract
 * itself is the repo-root `api-contract.ts`, which a consumer copies beside `api.d.ts`.
 *
 * The TYPES are not declared here. They live in the repo-root `api.d.ts`, which is the file a consumer
 * reads, and are re-exported from it so there is exactly one declaration of each and nothing to drift.
 */

import type { ApiContract } from '@mnaoumov/typescript-lib/api-contract';

import { CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT } from '../../api-contract.ts';

export type {
  AttachmentPathContext,
  CollectAttachmentsParams,
  CollectAttachmentUsedByMultipleNotesMode,
  CustomAttachmentLocationApi,
  GetAttachmentFolderPathParams,
  GetAvailablePathForAttachmentsParams,
  GetProperAttachmentPathParams,
  IsAttachmentUnitFolderParams,
  MigratableCollectSettings,
  MigrateSettingsParams,
  MigrateSettingsResult,
  MoveAttachmentToProperFolderUsedByMultipleNotesMode
} from '../../api.d.ts';

/**
 * The contract this plugin publishes: the repo-root `api-contract.ts` constant a consumer copies, so the
 * provider and its consumers validate against one definition. Assigning it here is also what checks that the
 * hand-written schemas are Standard Schemas the registry accepts.
 */
export const PLUGIN_API_CONTRACT: ApiContract = CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT;

export { PLUGIN_API_VERSION } from './plugin-api-version.ts';
