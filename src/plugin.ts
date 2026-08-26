import type { TAbstractFile } from 'obsidian';
import type { RenameDeleteHandlerSettings } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import type { TranslationsMap } from 'obsidian-dev-utils/obsidian/i18n/i18n';

import { OpenDemoVaultCommandHandler } from 'obsidian-dev-utils/obsidian/command-handlers/open-demo-vault-command-handler';
import { PluginSettingsTabComponent } from 'obsidian-dev-utils/obsidian/components/plugin-settings-tab-component';
import { RenameDeleteHandlerComponent } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import { PluginDataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import { PluginBase } from 'obsidian-dev-utils/obsidian/plugin/plugin';
import { PluginEventSourceImpl } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';
import { ValueWrapper } from 'obsidian-dev-utils/value-wrapper';

import { ArrayBufferMap } from './array-buffer-map.ts';
import { AttachmentCollector } from './attachment-collector.ts';
import { AttachmentPathManager } from './attachment-path-manager.ts';
import { AttachmentRescuer } from './attachment-rescue.ts';
import { AttachmentSaver } from './attachment-saver.ts';
import { CollectAttachmentsEntireVaultCommandHandler } from './command-handlers/collect-attachments-entire-vault-command-handler.ts';
import { CollectAttachmentsInCurrentFolderCommandHandler } from './command-handlers/collect-attachments-in-current-folder-command-handler.ts';
import { CollectAttachmentsInFileCommandHandler } from './command-handlers/collect-attachments-in-file-command-handler.ts';
import { DeleteUnusedAttachmentsEntireVaultCommandHandler } from './command-handlers/delete-unused-attachments-entire-vault-command-handler.ts';
import { DeleteUnusedAttachmentsInFileCommandHandler } from './command-handlers/delete-unused-attachments-in-file-command-handler.ts';
import { MoveAttachmentToProperFolderCommandHandler } from './command-handlers/move-attachment-to-proper-folder-command-handler.ts';
import { CustomAttachmentLocationComponent } from './custom-attachment-location-component.ts';
import { translationsMap } from './i18n/locales/translations-map.ts';
import { ImageManager } from './image-manager.ts';
import { ImageSizeMap } from './image-size-map.ts';
import { createLinkUpdateProgressReporter } from './link-update-progress-reporter.ts';
import { MarkdownUrlMap } from './markdown-url-map.ts';
import { NetworkImageDownloader } from './network-image-downloader.ts';
import { AppSaveAttachmentPatchComponent } from './patches/app-save-attachment-patch-component.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import { PluginSettingsTab } from './plugin-settings-tab.ts';
import { TokenValidator } from './token-validator.ts';
import { TokenizedStringLanguageComponent } from './tokenized-string-language-component.ts';
import { UnusedAttachmentsRemover } from './unused-attachments-remover.ts';

export class Plugin extends PluginBase {
  private attachmentCollector: AttachmentCollector | null = null;

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
   * @param abstractFiles - The notes, or folders of notes, to collect attachments for.
   */
  public collectAttachmentsInAbstractFiles(abstractFiles: TAbstractFile[]): void {
    this.attachmentCollector?.collectAttachmentsInAbstractFiles(abstractFiles);
  }

  protected override createTranslationsMap(): TranslationsMap {
    return translationsMap;
  }

  protected override async onloadImpl(): Promise<void> {
    const validatorWrapper = ValueWrapper.unset<TokenValidator>();

    const pluginSettingsComponent = this.addChild(
      new PluginSettingsComponent({
        app: this.app,
        dataHandler: new PluginDataHandler(this),
        pluginEventSource: new PluginEventSourceImpl(this),
        validatorWrapper
      })
    );
    this.pluginSettingsComponent = pluginSettingsComponent;

    const validator = new TokenValidator({
      app: this.app,
      pluginSettingsComponent
    });

    validatorWrapper.value = validator;

    const getAvailablePathForAttachmentsOriginal = this.app.vault.getAvailablePathForAttachments.bind(this.app.vault);

    const attachmentPathManager = new AttachmentPathManager({
      app: this.app,
      getAvailablePathForAttachmentsOriginal,
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
        imageSizeMap,
        markdownUrlMap,
        pluginDirectory: this.manifest.dir ?? '',
        pluginSettingsComponent,
        pluginVersion: this.manifest.version,
        tokenValidator: validator
      })
    );

    this.addChild(
      new PluginSettingsTabComponent({
        plugin: this,
        pluginSettingsTab: new PluginSettingsTab({
          plugin: this,
          pluginSettingsComponent
        })
      })
    );

    const attachmentRescuer = new AttachmentRescuer({
      app: this.app,
      attachmentPathManager,
      pluginSettingsComponent
    });

    this.addChild(
      new RenameDeleteHandlerComponent({
        abortSignalComponent: this.abortSignalComponent,
        app: this.app,
        linkUpdateProgressReporter: createLinkUpdateProgressReporter({
          pluginNoticeComponent: this.pluginNoticeComponent
        }),
        pluginId: this.manifest.id,
        pluginNoticeComponent: this.pluginNoticeComponent,
        resourceLockComponent: this.resourceLockComponent,
        settingsBuilder: (): Partial<RenameDeleteHandlerSettings> => ({
          emptyFolderBehavior: pluginSettingsComponent.settings.emptyFolderBehavior,
          getRescuePath: async (params) => await attachmentRescuer.getRescuePath(params),
          isNote: (path: string): boolean => pluginSettingsComponent.isNoteEx(path),
          isPathIgnored: (path: string): boolean => pluginSettingsComponent.settings.isPathIgnored(path),
          shouldHandleDeletions: pluginSettingsComponent.settings.shouldDeleteOrphanAttachments,
          shouldHandleRenames: pluginSettingsComponent.settings.shouldHandleRenames,
          shouldRenameAttachmentFiles: pluginSettingsComponent.settings.shouldRenameAttachmentFiles,
          shouldRenameAttachmentFolder: pluginSettingsComponent.settings.shouldRenameAttachmentFolder,
          shouldUpdateFileNameAliases: true
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
      networkImageDownloader,
      pluginName: this.manifest.name,
      pluginNoticeComponent: this.pluginNoticeComponent,
      pluginSettingsComponent,
      resourceLockComponent: this.resourceLockComponent
    });
    this.attachmentCollector = attachmentCollector;

    const unusedAttachmentsRemover = new UnusedAttachmentsRemover({
      abortSignalComponent: this.abortSignalComponent,
      app: this.app,
      attachmentPathManager,
      pluginName: this.manifest.name,
      pluginNoticeComponent: this.pluginNoticeComponent,
      pluginSettingsComponent
    });

    await this.commandHandlerComponent.registerCommandHandlers(() => [
      new CollectAttachmentsInFileCommandHandler({
        attachmentCollector
      }),
      new DeleteUnusedAttachmentsInFileCommandHandler({
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
        pluginNoticeComponent: this.pluginNoticeComponent,
        pluginSettingsComponent,
        resourceLockComponent: this.resourceLockComponent
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

    this.addChild(new TokenizedStringLanguageComponent());
  }
}
