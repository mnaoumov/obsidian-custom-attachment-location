import type {
  App,
  TAbstractFile
} from 'obsidian';

import {
  AttachmentPathContext,
  DUMMY_PATH
} from '@mnaoumov/obsidian-lib/attachment-path';
import {
  getAbstractFileOrNull,
  getFileOrNull
} from '@mnaoumov/obsidian-lib/file-system';
import { getBacklinksForFileSafe } from '@mnaoumov/obsidian-lib/metadata-cache';
import {
  noop,
  noopAsync
} from '@mnaoumov/typescript-lib/function';

import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { AttachmentPathManager } from '../attachment-location/attachment-path-manager.ts';
import type { AttachmentCollector } from '../collect/attachment-collector.ts';
import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type {
  AttachmentPathContext as AttachmentPathContextName,
  CollectAttachmentsParams,
  CustomAttachmentLocationApi,
  GetAttachmentFolderPathParams,
  GetAvailablePathForAttachmentsParams,
  GetProperAttachmentPathParams,
  IsAttachmentUnitFolderParams,
  MigrateSettingsParams,
  MigrateSettingsResult
} from './plugin-api.ts';

import { ActionContext } from '../tokens/token-evaluator-context.ts';
import { showCollectSettingsMigrationModal } from './collect-settings-migration-modal.ts';
import {
  applyMigrationRows,
  buildSettingsMigrationRows
} from './collect-settings-migration.ts';

/*
 * The published names, re-spelled under the names the params-interface convention wants. They are aliases
 * rather than separate declarations, so `api.d.ts` stays the single place either shape is described.
 */
type PluginApiImplCollectAttachmentsParams = CollectAttachmentsParams;

interface PluginApiImplConstructorParams {
  readonly app: App;
  readonly attachmentCollector: AttachmentCollector;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

type PluginApiImplGetAttachmentFolderPathParams = GetAttachmentFolderPathParams;

type PluginApiImplGetAvailablePathForAttachmentsParams = GetAvailablePathForAttachmentsParams;

type PluginApiImplGetProperAttachmentPathParams = GetProperAttachmentPathParams;

type PluginApiImplIsAttachmentUnitFolderParams = IsAttachmentUnitFolderParams;

/**
 * The published context names, mapped onto the library enum the resolver takes. Spelled out rather than cast, so a
 * name added on either side without the other fails to compile here.
 */
const ATTACHMENT_PATH_CONTEXTS: Readonly<Record<AttachmentPathContextName, AttachmentPathContext>> = {
  DeleteNote: AttachmentPathContext.DeleteNote,
  RenameNote: AttachmentPathContext.RenameNote,
  Unknown: AttachmentPathContext.Unknown
};

/**
 * The published API, implemented over the same {@link AttachmentPathManager} the plugin's own commands drive.
 *
 * Built in `onloadImpl` and handed to the base through `getPluginApis`, so the registry record lives exactly
 * as long as the feature surface does: while the declared dependency is missing this plugin registers nothing
 * and the handle is revoked, rather than answering from torn-down components.
 */
export class PluginApiImpl implements CustomAttachmentLocationApi {
  private readonly app: App;
  private readonly attachmentCollector: AttachmentCollector;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  /**
   * The tail of the dialog queue. Two proposals arriving at once would otherwise stack two dialogs, and the
   * second would compare against settings the first is about to change.
   */
  private queuedMigrations = noopAsync();

  public constructor(params: PluginApiImplConstructorParams) {
    this.app = params.app;
    this.attachmentCollector = params.attachmentCollector;
    this.attachmentPathManager = params.attachmentPathManager;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
   * Collects the attachments of the given notes and folders, as the `Collect attachments` commands do.
   *
   * @param params - What to collect.
   * @returns A promise that settles once the collect has finished.
   */
  public async collectAttachments(params: PluginApiImplCollectAttachmentsParams): Promise<void> {
    const abstractFiles: TAbstractFile[] = [];

    for (const pathOrFile of params.pathsOrFiles) {
      const abstractFile = getAbstractFileOrNull({ app: this.app, pathOrFile });
      if (abstractFile) {
        abstractFiles.push(abstractFile);
      }
    }

    /*
     * Nothing named exists, so there is nothing to collect. Handing the collector an empty list would not be
     * a no-op: several-or-none is what it confirms with the user, and that dialog would list no files.
     */
    if (abstractFiles.length === 0) {
      return;
    }

    await this.attachmentCollector.collectAttachmentsInAbstractFilesAndWait(abstractFiles);
  }

  /**
   * The folder this plugin would put a new attachment of the note's in.
   *
   * @param params - The note, and optionally the attachment whose name the template may read.
   * @returns The folder path, or `null` when this plugin leaves the note alone.
   */
  public async getAttachmentFolderPath(params: PluginApiImplGetAttachmentFolderPathParams): Promise<null | string> {
    /*
     * `DUMMY_PATH` for a caller that named no attachment, matching what the plugin itself passes when it has
     * none in hand — the folder template may read the attachment's name, and Obsidian's own placeholder is
     * what every other probe in this plugin resolves that with.
     */
    return this.handedOverSettingsComponent.isPathIgnored(params.notePath)
      ? null
      : await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
        actionContext: ActionContext.ReadApi,
        attachmentFileName: params.attachmentFileName ?? DUMMY_PATH,
        notePath: params.notePath
      });
  }

  /**
   * The full path this plugin's resolver gives an attachment.
   *
   * The same resolver the `getAvailablePathForAttachments` patch delegates to, and the replacement for the
   * `extended` member that patch grafted on until 15.0.0.
   *
   * @param params - The attachment, the note, and what to skip.
   * @returns The attachment's path.
   */
  public async getAvailablePathForAttachments(params: PluginApiImplGetAvailablePathForAttachmentsParams): Promise<string> {
    const { context, ...rest } = params;
    return await this.attachmentPathManager.getAvailablePathForAttachments({
      ...rest,
      context: ATTACHMENT_PATH_CONTEXTS[context]
    });
  }

  /**
   * Where an attachment a note already references belongs.
   *
   * @param params - The note, and the attachment it references.
   * @returns The path it belongs at, or `null` when there is nothing to do.
   */
  public async getProperAttachmentPath(params: PluginApiImplGetProperAttachmentPathParams): Promise<null | string> {
    if (this.handedOverSettingsComponent.isPathIgnored(params.notePath)) {
      return null;
    }

    const attachmentFile = getFileOrNull({ app: this.app, pathOrFile: params.attachmentPathOrFile });

    if (!attachmentFile || this.handedOverSettingsComponent.isPathIgnored(attachmentFile.path)) {
      return null;
    }

    /*
     * The reference is read from the attachment's backlinks rather than from the note's own link list, so a
     * frontmatter link and a canvas node count exactly as a body link does — the same source the
     * `Move attachment to proper folder` command reads, and the reason a consumer supplies two paths instead
     * of a `Reference` it would have to construct.
     */
    const backlinks = await getBacklinksForFileSafe({
      app: this.app,
      pathOrFile: attachmentFile
    });
    const reference = backlinks.get(params.notePath)?.[0];

    if (!reference) {
      return null;
    }

    const sequenceNumberByAttachmentPath = await this.attachmentPathManager.getSequenceNumberMap(params.notePath);

    return await this.attachmentPathManager.getProperAttachmentPath({
      actionContext: ActionContext.ReadApi,
      attachmentFile,
      noteFilePath: params.notePath,
      reference,
      sequenceNumber: sequenceNumberByAttachmentPath.get(attachmentFile.path) ?? 0
    });
  }

  /**
   * Whether the user designated the folder an attachment unit folder.
   *
   * @param params - The folder.
   * @returns Whether the folder is designated.
   */
  public isAttachmentUnitFolder(params: PluginApiImplIsAttachmentUnitFolderParams): boolean {
    return this.pluginSettingsComponent.settings.isAttachmentUnitFolder(params.folderPath);
  }

  /**
   * Offers the user the collect settings another plugin proposes, and applies what they approve.
   *
   * @param migrateSettingsParams - The proposal.
   * @returns What the user approved.
   */
  // eslint-disable-next-line typescript-dev-toolkit/params-options-name-match -- The type is the published contract's, shared with the interface this class implements; renaming it per class+method would rename it in every consumer.
  public async migrateSettings(migrateSettingsParams: MigrateSettingsParams): Promise<MigrateSettingsResult> {
    const previousMigrations = this.queuedMigrations;
    let releaseQueue: () => void = noop;
    this.queuedMigrations = new Promise<void>((resolve) => {
      releaseQueue = resolve;
    });

    await previousMigrations;

    try {
      return await this.migrateSettingsWithoutQueueing(migrateSettingsParams);
    } finally {
      releaseQueue();
    }
  }

  private getSourcePluginName(sourcePluginId: string): string {
    return this.app.plugins.manifests[sourcePluginId]?.name ?? sourcePluginId;
  }

  // eslint-disable-next-line typescript-dev-toolkit/params-options-name-match -- Same published contract type, one call deeper.
  private async migrateSettingsWithoutQueueing(migrateSettingsParams: MigrateSettingsParams): Promise<MigrateSettingsResult> {
    const rows = buildSettingsMigrationRows({
      currentSettings: this.pluginSettingsComponent.settings,
      proposedSettings: migrateSettingsParams.proposedSettings
    });

    /*
     * Nothing the proposal names differs from what this plugin already holds, so there is nothing to ask
     * about. The migration counts as done, and the caller may retire its pending proposal.
     */
    if (rows.length === 0) {
      return { isApplied: true };
    }

    const approvedRows = await showCollectSettingsMigrationModal({
      app: this.app,
      rows,
      sourcePluginName: this.getSourcePluginName(migrateSettingsParams.sourcePluginId)
    });

    if (!approvedRows) {
      return { isApplied: false };
    }

    await this.pluginSettingsComponent.editAndSave((settings) => {
      applyMigrationRows(settings, approvedRows);
    });

    return { isApplied: true };
  }
}
