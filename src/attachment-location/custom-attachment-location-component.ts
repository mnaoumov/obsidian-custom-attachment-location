import type { App } from 'obsidian';

import { DUMMY_PATH } from '@mnaoumov/obsidian-lib/attachment-path';
import { AllWindowsEventComponent } from '@mnaoumov/obsidian-lib/components/all-windows-event-component';
import { LayoutReadyComponent } from '@mnaoumov/obsidian-lib/components/layout-ready-component';
import { convertAsyncToSync } from '@mnaoumov/typescript-lib/async';
import { ViewType } from '@obsidian-typings/obsidian-public-latest/implementations';
import { webUtils } from 'electron';
import {
  MarkdownView,
  Menu,
  MenuItem,
  TFile
} from 'obsidian';

import type { HandedOverSettingsComponent } from '../advanced-rename-and-delete-handler/handed-over-settings-component.ts';
import type { ArrayBufferMap } from '../attachment-saving/array-buffer-map.ts';
import type { ImageSizeMap } from '../markdown-links/image-size-map.ts';
import type { MarkdownUrlMap } from '../markdown-links/markdown-url-map.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';

import { FileArrayBufferPatchComponent } from '../attachment-saving/file-array-buffer-patch-component.ts';
import { ExternallyCreatedAttachmentHandlerComponent } from '../externally-created-attachments/externally-created-attachment-handler-component.ts';
import { WriteAttributionPatchComponent } from '../externally-created-attachments/write-attribution-patch-component.ts';
import { FileManagerGenerateMarkdownLinkPatchComponent } from '../markdown-links/file-manager-generate-markdown-link-patch-component.ts';
import { AppImportAttachmentsPatchComponent } from '../pasted-images/app-import-attachments-patch-component.ts';
import { ClipboardManagerInsertFilesPatchComponent } from '../pasted-images/clipboard-manager-insert-files-patch-component.ts';
import { InsertGestureTrackerComponent } from '../pasted-images/insert-gesture-tracker-component.ts';
import { PastedImageMarker } from '../pasted-images/pasted-image-marker.ts';
import { WebUtilsGetPathForFilePatchComponent } from '../pasted-images/web-utils-get-path-for-file-patch-component.ts';
import { CoreFilesSettingTabPatchComponent } from '../settings/core-files-setting-tab-patch-component.ts';
import { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import { ActionContext } from '../tokens/token-evaluator-context.ts';
import { TokenValidator } from '../tokens/token-validator.ts';
import { ShareReceiverImportFilesPatchComponent } from './share-receiver-import-files-patch-component.ts';
import { VaultCreateBinaryEnsureFolderPatchComponent } from './vault-create-binary-ensure-folder-patch-component.ts';
import { VaultGetAvailablePathForAttachmentsPatchComponent } from './vault-get-available-path-for-attachments-patch-component.ts';
import { VaultGetAvailablePathPatchComponent } from './vault-get-available-path-patch-component.ts';
import { VaultGetConfigPatchComponent } from './vault-get-config-patch-component.ts';

interface CustomAttachmentLocationComponentConstructorParams {
  readonly app: App;
  readonly arrayBufferMap: ArrayBufferMap;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  readonly imageSizeMap: ImageSizeMap;
  readonly markdownUrlMap: MarkdownUrlMap;
  readonly pluginId: string;
  readonly pluginName: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly tokenValidator: TokenValidator;
}

export class CustomAttachmentLocationComponent extends LayoutReadyComponent {
  /**
   * The folder the `getConfig` patch hands Obsidian as its `attachmentFolderPath`, or `null` to leave Obsidian's
   * own value alone.
   *
   * Always `null` while the plugin follows Obsidian's own location. Otherwise the patch would feed Obsidian a
   * value resolved FROM Obsidian's setting back as that very setting — a loop that is easy to write and hard to
   * see. Checked here, at read time, rather than only when a note is opened, so a value cached before the mode
   * was switched on cannot outlive the switch.
   *
   * @returns The resolved folder, or `null`.
   */
  public get currentAttachmentFolderPath(): null | string {
    return this.pluginSettingsComponent.settings.shouldFollowObsidianAttachmentLocation ? null : this._currentAttachmentFolderPath;
  }

  private _currentAttachmentFolderPath: null | string = null;

  private readonly arrayBufferMap: ArrayBufferMap;

  private readonly attachmentPathManager: AttachmentPathManager;

  private readonly handedOverSettingsComponent: HandedOverSettingsComponent;
  private readonly imageSizeMap: ImageSizeMap;

  private readonly insertGestureTrackerComponent: InsertGestureTrackerComponent;

  private isMarkdownViewPatched = false;

  private lastOpenFilePath: null | string = null;

  private readonly markdownUrlMap: MarkdownUrlMap;
  private readonly pastedImageMarker: PastedImageMarker;
  private readonly pluginId: string;
  private readonly pluginName: string;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: CustomAttachmentLocationComponentConstructorParams) {
    super(params.app);
    this.arrayBufferMap = params.arrayBufferMap;
    this.handedOverSettingsComponent = params.handedOverSettingsComponent;
    this.pluginId = params.pluginId;
    this.pluginName = params.pluginName;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.attachmentPathManager = params.attachmentPathManager;
    this.markdownUrlMap = params.markdownUrlMap;
    this.imageSizeMap = params.imageSizeMap;
    this.tokenValidator = params.tokenValidator;
    this.insertGestureTrackerComponent = new InsertGestureTrackerComponent(params.app);
    this.pastedImageMarker = new PastedImageMarker({
      arrayBufferMap: this.arrayBufferMap,
      getScreenshotFilePaths: (): readonly string[] => this.pluginSettingsComponent.settings.screenshotFilePaths,
      getShouldKeepNamesOfPastedNonScreenshotFiles: (): boolean => this.pluginSettingsComponent.settings.shouldKeepNamesOfPastedNonScreenshotFiles
    });
  }

  public override onload(): void {
    super.onload();
    this.registerEvent(this.app.workspace.on('file-open', convertAsyncToSync(this.handleFileOpen.bind(this))));
    this.registerEvent(this.app.vault.on('rename', convertAsyncToSync(this.handleRename.bind(this))));

    this.registerEvent(this.app.workspace.on('receive-text-menu', this.handleReceiveTextMenu.bind(this)));
    this.registerEvent(this.app.workspace.on('receive-files-menu', this.handleReceiveFilesMenu.bind(this)));
  }

  protected override async onLayoutReady(): Promise<void> {
    // On an enable after layout-ready this runs while the settings component is still reading `data.json`, and the
    // patches below must not act on the defaults. Custom tokens need nothing here: the load registers them.
    await this.pluginSettingsComponent.whenLoadedFromFile();

    this.addChild(
      new VaultGetAvailablePathForAttachmentsPatchComponent({
        attachmentPathManager: this.attachmentPathManager,
        vault: this.app.vault
      })
    );

    this.addChild(
      new VaultCreateBinaryEnsureFolderPatchComponent({
        app: this.app,
        vault: this.app.vault
      })
    );

    /*
     * Before the handler that consumes what it records — and before any foreign write can happen, which is
     * why both live behind layout-ready rather than `onload`.
     */
    this.addChild(
      new WriteAttributionPatchComponent({
        pluginId: this.pluginId,
        pluginSettingsComponent: this.pluginSettingsComponent,
        vault: this.app.vault
      })
    );

    this.addChild(
      new ExternallyCreatedAttachmentHandlerComponent({
        app: this.app,
        attachmentPathManager: this.attachmentPathManager,
        handedOverSettingsComponent: this.handedOverSettingsComponent,
        pluginSettingsComponent: this.pluginSettingsComponent,
        tokenValidator: this.tokenValidator
      })
    );

    this.addChild(
      new VaultGetAvailablePathPatchComponent({
        app: this.app,
        pluginSettingsComponent: this.pluginSettingsComponent,
        vault: this.app.vault
      })
    );

    this.addChild(
      new VaultGetConfigPatchComponent({
        customAttachmentLocationComponent: this,
        vault: this.app.vault
      })
    );

    this.addChild(
      new CoreFilesSettingTabPatchComponent({
        app: this.app,
        pluginId: this.pluginId,
        pluginName: this.pluginName,
        pluginSettingsComponent: this.pluginSettingsComponent
      })
    );

    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Actually not available on some platforms.
    if (webUtils) {
      this.addChild(
        new WebUtilsGetPathForFilePatchComponent({
          webUtils
        })
      );
    }

    this.addChild(
      new FileManagerGenerateMarkdownLinkPatchComponent({
        app: this.app,
        attachmentPathManager: this.attachmentPathManager,
        fileManager: this.app.fileManager,
        imageSizeMap: this.imageSizeMap,
        markdownUrlMap: this.markdownUrlMap,
        pluginSettingsComponent: this.pluginSettingsComponent
      })
    );

    this.addChild(
      new ShareReceiverImportFilesPatchComponent({
        app: this.app,
        attachmentPathManager: this.attachmentPathManager,
        pluginSettingsComponent: this.pluginSettingsComponent,
        shareReceiver: this.app.shareReceiver,
        tokenValidator: this.tokenValidator
      })
    );

    this.addChild(this.insertGestureTrackerComponent);

    this.addChild(
      new AppImportAttachmentsPatchComponent({
        app: this.app,
        insertGestureTrackerComponent: this.insertGestureTrackerComponent,
        pastedImageMarker: this.pastedImageMarker
      })
    );

    this.addChild(new AllWindowsEventComponent(this.app)).registerAllDocumentsDomEvent({
      callback: this.handleInputFileChange.bind(this),
      options: { capture: true },
      type: 'change'
    });

    this.patchClipboardManagerFromLoadedMarkdownView();

    if (this.isMarkdownViewPatched) {
      return;
    }

    const handler = this.patchClipboardManagerFromLoadedMarkdownView.bind(this);
    this.registerEvent(this.app.workspace.on('active-leaf-change', handler));
    this.registerEvent(this.app.workspace.on('layout-change', handler));
  }

  private async handleFileOpen(file: null | TFile): Promise<void> {
    if (
      file === null || this.handedOverSettingsComponent.isPathIgnored(file.path)
      || this.pluginSettingsComponent.settings.shouldFollowObsidianAttachmentLocation
    ) {
      this._currentAttachmentFolderPath = null;
      this.lastOpenFilePath = null;
      return;
    }

    if (file.path === this.lastOpenFilePath) {
      return;
    }

    this.lastOpenFilePath = file.path;
    this._currentAttachmentFolderPath = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
      actionContext: ActionContext.OpenFile,
      attachmentFileName: DUMMY_PATH,
      notePath: file.path
    });
  }

  private handleInputFileChange($event: Event): void {
    if (!($event.target instanceof HTMLInputElement) || $event.target.type !== 'file') {
      return;
    }

    for (const file of $event.target.files ?? []) {
      this.addChild(
        new FileArrayBufferPatchComponent({
          app: this.app,
          arrayBufferMap: this.arrayBufferMap,
          file
        })
      );
    }
  }

  private handleReceiveFilesMenu(menu: Menu, attachmentFiles: TFile[]): void {
    this.handleReceiveMenuItemClick(menu, (noteFile) => {
      const linkTexts = attachmentFiles.map((attachmentFile) => this.app.fileManager.generateMarkdownLink(attachmentFile, noteFile.path));
      return linkTexts.join('\n');
    });
  }

  private handleReceiveMenuItemClick(menu: Menu, prepareTextFunction: (noteFile: TFile) => string): void {
    const app = this.app;
    const menuItem = menu.items.find((item) => item instanceof MenuItem && !!item.iconEl.querySelector('.lucide-file')) as MenuItem | undefined;
    if (menuItem) {
      menuItem.callback = callback;
    }

    function callback(): void {
      const markdownView = app.workspace.getActiveViewOfType(MarkdownView);
      if (!markdownView?.file) {
        return;
      }

      const text = prepareTextFunction(markdownView.file);
      markdownView.editor.replaceSelection(text);
    }
  }

  private handleReceiveTextMenu(menu: Menu, text: string): void {
    this.handleReceiveMenuItemClick(menu, () => text);
  }

  private async handleRename(): Promise<void> {
    await this.handleFileOpen(this.app.workspace.getActiveFile());
  }

  /**
   * Patches the clipboard manager's prototype, which only a loaded markdown view can reach.
   *
   * A background tab stays deferred until it is shown, and it is never loaded here. Loading one restores its saved
   * selection, and another plugin may have stored that selection against an older version of the note, so the load
   * threw at startup with `Selection points outside of document`. The events registered in `onLayoutReady` retry once
   * Obsidian loads a markdown view itself, which it does before anyone can paste into it.
   */
  private patchClipboardManagerFromLoadedMarkdownView(): void {
    if (this.isMarkdownViewPatched) {
      return;
    }

    const leaf = this.app.workspace.getLeavesOfType(ViewType.Markdown).find((candidate) => !candidate.isDeferred && candidate.view.getViewType() === ViewType.Markdown);
    if (!leaf) {
      return;
    }

    const markdownView = leaf.view as MarkdownView;

    this.addChild(
      new ClipboardManagerInsertFilesPatchComponent({
        clipboardManager: markdownView.editMode.clipboardManager,
        insertGestureTrackerComponent: this.insertGestureTrackerComponent,
        pastedImageMarker: this.pastedImageMarker
      })
    );

    this.isMarkdownViewPatched = true;
  }
}
