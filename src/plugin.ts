import type {
  PluginConflict,
  PluginDependency,
  PluginGateComponent
} from '@mnaoumov/obsidian-lib/components/plugin-gate-component';
import type { TranslationsMap } from '@mnaoumov/obsidian-lib/i18n/i18n';
import type { PluginApiDeclaration } from '@mnaoumov/obsidian-lib/plugin/plugin-api';
import type { TAbstractFile } from 'obsidian';

import { OpenDemoVaultCommandHandler } from '@mnaoumov/obsidian-lib/command-handlers/open-demo-vault-command-handler';
import { PluginConflictSeverity } from '@mnaoumov/obsidian-lib/components/plugin-gate-component';
import { PluginSettingsTabComponent } from '@mnaoumov/obsidian-lib/components/plugin-settings-tab-component';
import { SettingsMigrationComponent } from '@mnaoumov/obsidian-lib/components/settings-migration-component';
import { PluginDataHandler } from '@mnaoumov/obsidian-lib/data-handler';
import {
  asCodeBlock,
  createFragmentWithCodeBlocks
} from '@mnaoumov/obsidian-lib/html-element';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { PluginBase } from '@mnaoumov/obsidian-lib/plugin/plugin';
import { PluginEventSourceImpl } from '@mnaoumov/obsidian-lib/plugin/plugin-event-source';
import { join } from '@mnaoumov/typescript-lib/path';
import { ValueWrapper } from '@mnaoumov/typescript-lib/value-wrapper';
import {
  Component,
  normalizePath
} from 'obsidian';

import type {
  AdvancedRenameAndDeleteHandlerMigratableSettings,
  MigratableSettings
} from './advanced-rename-and-delete-handler.ts';

import {
  ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE,
  ADVANCED_RENAME_AND_DELETE_HANDLER_DEPENDENCY_API_VERSION_RANGE,
  ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT,
  ADVANCED_RENAME_AND_DELETE_HANDLER_MIN_PLUGIN_VERSION,
  ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
  ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME
} from './advanced-rename-and-delete-handler.ts';
import { ArrayBufferMap } from './array-buffer-map.ts';
import { AttachmentCollector } from './attachment-collector.ts';
import { AttachmentPathManager } from './attachment-path-manager.ts';
import { AttachmentSaver } from './attachment-saver.ts';
import { AutomaticAttachmentCollectorComponent } from './automatic-attachment-collector-component.ts';
import { CollectAttachmentsEntireVaultCommandHandler } from './command-handlers/collect-attachments-entire-vault-command-handler.ts';
import { CollectAttachmentsInCurrentFolderCommandHandler } from './command-handlers/collect-attachments-in-current-folder-command-handler.ts';
import { CollectAttachmentsInFileCommandHandler } from './command-handlers/collect-attachments-in-file-command-handler.ts';
import { DeleteUnusedAttachmentsEntireVaultCommandHandler } from './command-handlers/delete-unused-attachments-entire-vault-command-handler.ts';
import { DeleteUnusedAttachmentsInFileCommandHandler } from './command-handlers/delete-unused-attachments-in-file-command-handler.ts';
import { GoToAttachmentFolderCommandHandler } from './command-handlers/go-to-attachment-folder-command-handler.ts';
import { GoToOwningNoteCommandHandler } from './command-handlers/go-to-owning-note-command-handler.ts';
import { MoveAttachmentToProperFolderCommandHandler } from './command-handlers/move-attachment-to-proper-folder-command-handler.ts';
import { PruneOriginalAttachmentNamesCommandHandler } from './command-handlers/prune-original-attachment-names-command-handler.ts';
import { RememberCurrentNameAsOriginalCommandHandler } from './command-handlers/remember-current-name-as-original-command-handler.ts';
import { ShowOriginalAttachmentNamesCommandHandler } from './command-handlers/show-original-attachment-names-command-handler.ts';
import {
  CONSISTENT_ATTACHMENTS_AND_LINKS_COLLECTING_VERSION_RANGE,
  CONSISTENT_ATTACHMENTS_AND_LINKS_PLUGIN_ID,
  CONSISTENT_ATTACHMENTS_AND_LINKS_PLUGIN_NAME
} from './consistent-attachments-and-links.ts';
import { CustomAttachmentLocationComponent } from './custom-attachment-location-component.ts';
import { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import { translationsMap } from './i18n/locales/translations-map.ts';
import { ImageManager } from './image-manager.ts';
import { ImageSizeMap } from './image-size-map.ts';
import { MarkdownUrlMap } from './markdown-url-map.ts';
import { NetworkImageDownloader } from './network-image-downloader.ts';
import { NoteOwnerResolver } from './note-owner-resolver.ts';
import {
  ORIGINAL_ATTACHMENT_NAMES_FILE_NAME,
  OriginalAttachmentNamesComponent
} from './original-attachment-names-component.ts';
import { AppSaveAttachmentPatchComponent } from './patches/app-save-attachment-patch-component.ts';
import { PluginApiImpl } from './plugin-api-impl.ts';
import {
  PLUGIN_API_CONTRACT,
  PLUGIN_API_VERSION
} from './plugin-api.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import { PluginSettingsTab } from './plugin-settings-tab.ts';
import { createReleaseNotesComponent } from './release-notes-component.ts';
import { TokenValidator } from './token-validator.ts';
import { createTokenizedStringLanguageComponent } from './tokenized-string-language.ts';
import { UnusedAttachmentsRemover } from './unused-attachments-remover.ts';

export class Plugin extends PluginBase {
  private attachmentCollector: AttachmentCollector | null = null;
  private pluginApi: null | PluginApiImpl = null;

  /**
   * Collects the attachments of the given notes into the folders the settings say they belong in,
   * exactly as the **Collect attachments in current note** command does.
   *
   * This is the plugin's public surface for other plugins. It exists because the command itself acts
   * on the ACTIVE file, so a caller that wants a specific note collected would otherwise have to open
   * it first — a visible side effect of an unrelated operation. Reached as:
   *
   * ```ts
   * const plugin = app.plugins.getPlugin('obsidian-custom-attachment-location');
   * // Check the method is there before calling it: the user may have an older version, or none.
   * plugin?.collectAttachmentsInAbstractFiles?.([noteFile]);
   * ```
   *
   * The work is queued rather than awaited, matching the command, so this returns immediately.
   *
   * Superseded by the published API's `collectAttachments`, declared in `api.d.ts`, versioned, and revoked when
   * this plugin unloads, where this method is a duck-typed reach into the plugin instance. Kept, delegating to
   * the same collector, for callers written before contract version `1.2.0`; new callers use the API.
   *
   * @param abstractFiles - The notes, or folders of notes, to collect attachments for.
   */
  public collectAttachmentsInAbstractFiles(abstractFiles: TAbstractFile[]): void {
    this.attachmentCollector?.collectAttachmentsInAbstractFiles(abstractFiles);
  }

  protected override createTranslationsMap(): TranslationsMap {
    return translationsMap;
  }

  /**
   * Declares the API for the base to publish, once `onloadImpl` has built it.
   *
   * Published by the base rather than by hand: the `plugin-loaded` broadcast's `apiVersions` is derived from
   * this method alone, so a hand `publishPluginApi` call would announce this plugin as publishing no API at
   * all — while the registry still worked, which is what makes that mistake invisible.
   *
   * @returns The declaration, or none while the feature surface is down.
   */
  protected override getPluginApis(): PluginApiDeclaration[] {
    return this.pluginApi
      ? [
        {
          api: this.pluginApi,
          apiVersion: PLUGIN_API_VERSION,
          contract: PLUGIN_API_CONTRACT
        }
      ]
      : [];
  }

  protected override getPluginConflicts(): PluginConflict[] {
    return [
      {
        conflictingVersionRange: CONSISTENT_ATTACHMENTS_AND_LINKS_COLLECTING_VERSION_RANGE,
        pluginId: CONSISTENT_ATTACHMENTS_AND_LINKS_PLUGIN_ID,
        pluginName: CONSISTENT_ATTACHMENTS_AND_LINKS_PLUGIN_NAME,
        reason: t(($) => $.pluginConflict.consistentAttachmentsAndLinks.reason),
        severity: PluginConflictSeverity.Warn
      }
    ];
  }

  /**
   * Declares `Advanced Rename and Delete Handler` as a dependency this plugin cannot run without.
   *
   * It owns renames and deletions since 12.0.0, and the settings this plugin's own commands read back. Without
   * it, a note's attachment folder silently stops following the note — and nothing would connect that to a
   * plugin removed weeks earlier. Declared, this plugin does nothing while it is missing, says why, and installs
   * it in one click.
   *
   * @returns The dependency.
   */
  protected override getPluginDependencies(): PluginDependency[] {
    return [
      {
        apiVersionRange: ADVANCED_RENAME_AND_DELETE_HANDLER_DEPENDENCY_API_VERSION_RANGE,
        minPluginVersion: ADVANCED_RENAME_AND_DELETE_HANDLER_MIN_PLUGIN_VERSION,
        pluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
        pluginName: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME,
        reason: createFragmentWithCodeBlocks(t(($) => $.pluginDependency.advancedRenameAndDeleteHandler.reason, {
          dependencyPluginName: asCodeBlock(ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_NAME),
          pluginName: asCodeBlock(this.manifest.name)
        }))
      }
    ];
  }

  protected override async onloadImpl(): Promise<void> {
    const validatorWrapper = ValueWrapper.unset<TokenValidator>();

    // Before the settings component, which reads back through it: `isNoteEx` consults the attachment-extension
    // list that `Advanced Rename and Delete Handler` owns since 12.0.0.
    const handedOverSettingsComponent = this.addChild(
      new HandedOverSettingsComponent({
        app: this.app
      })
    );

    const pluginSettingsComponent = this.addChild(
      new PluginSettingsComponent({
        app: this.app,
        dataHandler: new PluginDataHandler(this),
        handedOverSettingsComponent,
        pluginEventSource: new PluginEventSourceImpl(this),
        validatorWrapper
      })
    );
    this.pluginSettingsComponent = pluginSettingsComponent;

    this.addChild(
      new SettingsMigrationComponent<AdvancedRenameAndDeleteHandlerMigratableSettings>({
        apiVersionRange: ADVANCED_RENAME_AND_DELETE_HANDLER_API_VERSION_RANGE,
        app: this.app,
        // Names only what migrating needs, `migrateSettings`. The dependency gate already insists on a provider
        // new enough for the read-back, so this cannot widen who is offered the migration; it only keeps the
        // migration from claiming to need what it does not use.
        contract: ADVANCED_RENAME_AND_DELETE_HANDLER_MIGRATION_API_CONTRACT,
        getProposedSettings: (): MigratableSettings | null => pluginSettingsComponent.settings.proposedRenameDeleteSettings,
        pluginSettingsComponent,
        providerPluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
        retireProposedSettings: async (): Promise<void> => {
          await pluginSettingsComponent.editAndSave((settings) => {
            settings.proposedRenameDeleteSettings = null;
          });
        },
        sourcePluginId: this.manifest.id
      })
    );

    const validator = new TokenValidator({
      app: this.app,
      pluginSettingsComponent
    });

    validatorWrapper.value = validator;

    const getAvailablePathForAttachmentsOriginal = this.app.vault.getAvailablePathForAttachments.bind(this.app.vault);

    // Read before anything can ask for a name, and kept in a file of its own: it grows with the vault, the settings do not.
    const originalAttachmentNamesComponent = new OriginalAttachmentNamesComponent({
      app: this.app,
      consoleDebugComponent: this.consoleDebugComponent,
      pluginNoticeComponent: this.pluginNoticeComponent,
      pluginSettingsComponent,
      storeFilePath: normalizePath(join(this.manifest.dir ?? '', ORIGINAL_ATTACHMENT_NAMES_FILE_NAME))
    });
    await originalAttachmentNamesComponent.loadFromDisk();
    this.addChild(originalAttachmentNamesComponent);

    const attachmentPathManager = new AttachmentPathManager({
      app: this.app,
      getAvailablePathForAttachmentsOriginal,
      handedOverSettingsComponent,
      originalAttachmentNamesComponent,
      pluginNoticeComponent: this.pluginNoticeComponent,
      pluginSettingsComponent,
      tokenValidator: validator
    });

    const arrayBufferMap = new ArrayBufferMap({
      app: this.app
    });

    const imageSizeMap = new ImageSizeMap();
    const markdownUrlMap = new MarkdownUrlMap();
    const imageManager = new ImageManager({
      pluginSettingsComponent
    });

    const attachmentSaver = new AttachmentSaver({
      app: this.app,
      arrayBufferMap,
      attachmentPathManager,
      handedOverSettingsComponent,
      imageManager,
      imageSizeMap,
      markdownUrlMap,
      pluginSettingsComponent,
      tokenValidator: validator
    });

    this.addChild(
      new CustomAttachmentLocationComponent({
        app: this.app,
        arrayBufferMap,
        attachmentPathManager,
        handedOverSettingsComponent,
        imageSizeMap,
        markdownUrlMap,
        pluginId: this.manifest.id,
        pluginName: this.manifest.name,
        pluginSettingsComponent,
        tokenValidator: validator
      })
    );

    this.addChild(
      createReleaseNotesComponent({
        app: this.app,
        pluginDirectory: this.manifest.dir ?? '',
        pluginName: this.manifest.name,
        pluginSettingsComponent,
        pluginVersion: this.manifest.version
      })
    );

    this.addChild(
      new PluginSettingsTabComponent({
        plugin: this,
        pluginSettingsTab: new PluginSettingsTab({
          // Deliberately lazy: the gate is what loads this method, so the base has not assigned it yet.
          getPluginGateComponent: (): PluginGateComponent => this.pluginGateComponent,
          plugin: this,
          pluginSettingsComponent
        })
      })
    );

    const networkImageDownloader = new NetworkImageDownloader({
      abortSignalComponent: this.abortSignalComponent,
      app: this.app,
      attachmentPathManager,
      pluginSettingsComponent
    });

    const attachmentCollector = new AttachmentCollector({
      abortSignalComponent: this.abortSignalComponent,
      app: this.app,
      attachmentPathManager,
      consoleDebugComponent: this.consoleDebugComponent,
      handedOverSettingsComponent,
      networkImageDownloader,
      pluginNoticeComponent: this.pluginNoticeComponent,
      pluginSettingsComponent,
      resourceLockComponent: this.resourceLockComponent
    });
    this.attachmentCollector = attachmentCollector;

    this.addChild(
      new AutomaticAttachmentCollectorComponent({
        app: this.app,
        attachmentCollector,
        pluginSettingsComponent
      })
    );

    // Unloads with the feature surface, which goes whenever the dependency goes away — and this method runs
    // again when it comes back. Whatever this method leaves outside its own children is undone here.
    const featureSurfaceLifetimeComponent = this.addChild(new Component());

    // The field is read by `collectAttachmentsInAbstractFiles`, so it is cleared with the surface: the method
    // does nothing in between rather than driving a collector whose components have been torn down.
    featureSurfaceLifetimeComponent.register(() => {
      this.attachmentCollector = null;
    });

    /*
     * The published API, built here so the base can hand it out in `getPluginApis` — and cleared with the
     * surface for the same reason the collector is, since it drives the same components.
     */
    this.pluginApi = new PluginApiImpl({
      app: this.app,
      attachmentCollector,
      attachmentPathManager,
      handedOverSettingsComponent,
      pluginSettingsComponent
    });
    featureSurfaceLifetimeComponent.register(() => {
      this.pluginApi = null;
    });

    const unusedAttachmentsRemover = new UnusedAttachmentsRemover({
      abortSignalComponent: this.abortSignalComponent,
      app: this.app,
      attachmentPathManager,
      handedOverSettingsComponent,
      pluginNoticeComponent: this.pluginNoticeComponent,
      pluginSettingsComponent
    });

    const noteOwnerResolver = new NoteOwnerResolver({
      app: this.app,
      handedOverSettingsComponent,
      pluginSettingsComponent
    });

    await this.commandHandlerComponent.registerCommandHandlers(() => [
      new CollectAttachmentsInFileCommandHandler({
        attachmentCollector
      }),
      new DeleteUnusedAttachmentsInFileCommandHandler({
        pluginSettingsComponent,
        unusedAttachmentsRemover
      }),
      new CollectAttachmentsInCurrentFolderCommandHandler({
        attachmentCollector
      }),
      new CollectAttachmentsEntireVaultCommandHandler({
        attachmentCollector
      }),
      new DeleteUnusedAttachmentsEntireVaultCommandHandler({
        unusedAttachmentsRemover
      }),
      new MoveAttachmentToProperFolderCommandHandler({
        abortSignalComponent: this.abortSignalComponent,
        app: this.app,
        attachmentPathManager,
        handedOverSettingsComponent,
        pluginNoticeComponent: this.pluginNoticeComponent,
        pluginSettingsComponent,
        resourceLockComponent: this.resourceLockComponent
      }),
      new GoToAttachmentFolderCommandHandler({
        app: this.app,
        attachmentPathManager,
        handedOverSettingsComponent,
        pluginNoticeComponent: this.pluginNoticeComponent,
        pluginSettingsComponent
      }),
      new GoToOwningNoteCommandHandler({
        app: this.app,
        noteOwnerResolver,
        pluginNoticeComponent: this.pluginNoticeComponent,
        pluginSettingsComponent
      }),
      new ShowOriginalAttachmentNamesCommandHandler({
        app: this.app,
        originalAttachmentNamesComponent,
        pluginNoticeComponent: this.pluginNoticeComponent,
        tokenValidator: validator
      }),
      new PruneOriginalAttachmentNamesCommandHandler({
        app: this.app,
        originalAttachmentNamesComponent,
        pluginNoticeComponent: this.pluginNoticeComponent
      }),
      new RememberCurrentNameAsOriginalCommandHandler({
        originalAttachmentNamesComponent,
        pluginNoticeComponent: this.pluginNoticeComponent,
        pluginSettingsComponent
      }),
      new OpenDemoVaultCommandHandler({
        app: this.app,
        pluginId: this.manifest.id,
        pluginNoticeComponent: this.pluginNoticeComponent,
        pluginVersion: this.manifest.version
      })
    ]);

    this.addChild(
      new AppSaveAttachmentPatchComponent({
        app: this.app,
        attachmentSaver
      })
    );

    this.addChild(createTokenizedStringLanguageComponent());
  }
}
