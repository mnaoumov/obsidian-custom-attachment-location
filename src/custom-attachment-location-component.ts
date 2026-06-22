import type {
  App,
  WorkspaceLeaf
} from 'obsidian';

import { ViewType } from '@obsidian-typings/obsidian-public-latest/implementations';
import { webUtils } from 'electron';
import {
  MarkdownView,
  Menu,
  MenuItem,
  TFile
} from 'obsidian';
import { convertAsyncToSync } from 'obsidian-dev-utils/async';
import { appendCodeBlock } from 'obsidian-dev-utils/html-element';
import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import { AllWindowsEventComponent } from 'obsidian-dev-utils/obsidian/components/all-windows-event-component';
import { LayoutReadyComponent } from 'obsidian-dev-utils/obsidian/components/layout-ready-component';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { alert } from 'obsidian-dev-utils/obsidian/modals/alert';
import { compare } from 'semver';

import type { ArrayBufferMap } from './array-buffer-map.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { AttachmentSaver } from './attachment-saver.ts';
import type { ImageSizeMap } from './image-size-map.ts';
import type { MarkdownUrlMap } from './markdown-url-map.ts';

import { ClipboardManagerInsertFilesPatchComponent } from './patches/clipboard-manager-insert-files-patch-component.ts';
import { FileArrayBufferPatchComponent } from './patches/file-array-buffer-patch-component.ts';
import { FileManagerGenerateMarkdownLinkPatchComponent } from './patches/file-manager-generate-markdown-link-patch-component.ts';
import { ShareReceiverImportFilesPatchComponent } from './patches/share-receiver-import-files-patch-component.ts';
import { VaultGetAvailablePathForAttachmentsPatchComponent } from './patches/vault-get-available-path-for-attachments-patch-component.ts';
import { VaultGetAvailablePathPatchComponent } from './patches/vault-get-available-path-patch-component.ts';
import { VaultGetConfigPatchComponent } from './patches/vault-get-config-patch-component.ts';
import { WebUtilsGetPathForFilePatchComponent } from './patches/web-utils-get-path-for-file-patch-component.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import { Substitutions } from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';

interface CustomAttachmentLocationComponentConstructorParams {
  readonly app: App;
  readonly arrayBufferMap: ArrayBufferMap;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly attachmentSaver: AttachmentSaver;
  readonly imageSizeMap: ImageSizeMap;
  readonly markdownUrlMap: MarkdownUrlMap;
  readonly pluginDir: string;
  readonly pluginName: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly pluginVersion: string;
}

export class CustomAttachmentLocationComponent extends LayoutReadyComponent {
  public readonly pluginDir: string;
  public readonly pluginName: string;
  public readonly pluginVersion: string;

  public get currentAttachmentFolderPath(): null | string {
    return this._currentAttachmentFolderPath;
  }

  private _currentAttachmentFolderPath: null | string = null;

  private readonly arrayBufferMap: ArrayBufferMap;

  private readonly attachmentPathManager: AttachmentPathManager;

  private readonly attachmentSaver: AttachmentSaver;
  private readonly imageSizeMap: ImageSizeMap;
  private isMarkdownViewPatched = false;
  private lastOpenFilePath: null | string = null;
  private readonly markdownUrlMap: MarkdownUrlMap;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CustomAttachmentLocationComponentConstructorParams) {
    super(params.app);
    this.arrayBufferMap = params.arrayBufferMap;
    this.attachmentSaver = params.attachmentSaver;
    this.pluginName = params.pluginName;
    this.pluginVersion = params.pluginVersion;
    this.pluginDir = params.pluginDir;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.attachmentPathManager = params.attachmentPathManager;
    this.markdownUrlMap = params.markdownUrlMap;
    this.imageSizeMap = params.imageSizeMap;
  }

  public override onload(): void {
    super.onload();
    this.registerEvent(this.app.workspace.on('file-open', convertAsyncToSync(this.handleFileOpen.bind(this))));
    this.registerEvent(this.app.vault.on('rename', convertAsyncToSync(this.handleRename.bind(this))));

    this.registerEvent(this.app.workspace.on('receive-text-menu', this.handleReceiveTextMenu.bind(this)));
    this.registerEvent(this.app.workspace.on('receive-files-menu', this.handleReceiveFilesMenu.bind(this)));
  }

  protected override async onLayoutReady(): Promise<void> {
    Substitutions.registerCustomTokens(this.pluginSettingsComponent.settings.customTokensStr);
    await this.pluginSettingsComponent.loadFromFile(false);

    this.addChild(
      new VaultGetAvailablePathForAttachmentsPatchComponent({
        attachmentSaver: this.attachmentSaver,
        vault: this.app.vault
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
        shareReceiver: this.app.shareReceiver
      })
    );

    this.addChild(new AllWindowsEventComponent(this.app)).registerAllDocumentsDomEvent('change', this.handleInputFileChange.bind(this), { capture: true });

    await this.handleActiveLeafChange(this.app.workspace.getLeavesOfType(ViewType.Markdown)[0] ?? null);

    if (!this.isMarkdownViewPatched) {
      this.registerEvent(this.app.workspace.on('active-leaf-change', convertAsyncToSync(this.handleActiveLeafChange.bind(this))));
    }

    await this.showReleaseNotes();
  }

  private async handleActiveLeafChange(leaf: null | WorkspaceLeaf): Promise<void> {
    if (this.isMarkdownViewPatched) {
      return;
    }

    if (!leaf) {
      return;
    }

    if (leaf.view.getViewType() !== ViewType.Markdown) {
      return;
    }

    await leaf.loadIfDeferred();

    const markdownView = leaf.view as MarkdownView;

    this.addChild(
      new ClipboardManagerInsertFilesPatchComponent({
        arrayBufferMap: this.arrayBufferMap,
        clipboardManager: markdownView.editMode.clipboardManager
      })
    );

    this.isMarkdownViewPatched = true;
  }

  private async handleFileOpen(file: null | TFile): Promise<void> {
    if (file === null || this.pluginSettingsComponent.settings.isPathIgnored(file.path)) {
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

  private handleInputFileChange(evt: Event): void {
    if (!(evt.target instanceof HTMLInputElement)) {
      return;
    }

    if (evt.target.type !== 'file') {
      return;
    }

    for (const file of evt.target.files ?? []) {
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

  private handleReceiveMenuItemClick(menu: Menu, prepareTextFn: (noteFile: TFile) => string): void {
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

      const text = prepareTextFn(markdownView.file);
      markdownView.editor.replaceSelection(text);
    }
  }

  private handleReceiveTextMenu(menu: Menu, text: string): void {
    this.handleReceiveMenuItemClick(menu, () => text);
  }

  private async handleRename(): Promise<void> {
    await this.handleFileOpen(this.app.workspace.getActiveFile());
  }

  private async showReleaseNotes(): Promise<void> {
    const RELEASE_NOTES: Record<string, DocumentFragment> = {
      /* eslint-disable perfectionist/sort-objects -- Need to keep versions in order. */
      '9.0.0': createFragment((f) => {
        f.appendText(t(($) => $.pluginSettingsManager.customToken.deprecated.part1));
        f.createEl('a', {
          href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#custom-tokens',
          text: t(($) => $.pluginSettingsManager.customToken.deprecated.part2)
        });
        f.appendText(' ');
        f.appendText(t(($) => $.pluginSettingsManager.customToken.deprecated.part3));
        f.createEl('br');
        f.appendText(t(($) => $.pluginSettingsManager.legacyRenameAttachmentsToLowerCase.part1));
        f.appendText(' ');
        appendCodeBlock(f, t(($) => $.pluginSettingsTab.renameAttachmentsToLowerCase));
        f.appendText(' ');
        f.appendText(t(($) => $.pluginSettingsManager.legacyRenameAttachmentsToLowerCase.part2));
        f.appendText(' ');
        appendCodeBlock(f, 'lower');
        f.appendText(' ');
        f.appendText(t(($) => $.pluginSettingsManager.legacyRenameAttachmentsToLowerCase.part3));
        f.appendText(' ');
        f.createEl('a', {
          href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#tokens',
          text: t(($) => $.pluginSettingsManager.legacyRenameAttachmentsToLowerCase.part4)
        });
        f.appendText(' ');
        f.appendText(t(($) => $.pluginSettingsManager.legacyRenameAttachmentsToLowerCase.part5));
      }),
      '9.2.0': createFragment((f) => {
        f.appendText(t(($) => $.pluginSettingsManager.markdownUrlFormat.deprecated.part1));
        appendCodeBlock(f, t(($) => $.pluginSettingsTab.markdownUrlFormat.name));
        f.appendText(t(($) => $.pluginSettingsManager.markdownUrlFormat.deprecated.part2));
        f.createEl('a', {
          href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#markdown-url-format',
          text: t(($) => $.pluginSettingsManager.markdownUrlFormat.deprecated.part3)
        });
        f.appendText(' ');
        f.appendText(t(($) => $.pluginSettingsManager.markdownUrlFormat.deprecated.part4));
        f.appendText(' ');
        f.appendText(t(($) => $.pluginSettingsManager.markdownUrlFormat.deprecated.part5));
      }),
      '9.16.0': createFragment((f) => {
        f.appendText(t(($) => $.pluginSettingsManager.specialCharacters.part1));
        appendCodeBlock(f, t(($) => $.pluginSettingsTab.specialCharacters.name));
        f.appendText(t(($) => $.pluginSettingsManager.specialCharacters.part2));
      }),
      '10.0.0': createFragment((f) => {
        f.appendText(t(($) => $.releaseNotes.versions['10.0.0'].part1));
        f.appendText(' ');
        f.createEl('a', {
          href: 'https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#tokens',
          text: t(($) => $.releaseNotes.versions['10.0.0'].part2)
        });
        f.appendText(' ');
        f.appendText(t(($) => $.releaseNotes.versions['10.0.0'].part3));
      })
      /* eslint-enable perfectionist/sort-objects -- Need to keep versions in order. */
    };

    const releaseNotes = createFragment();
    let shouldShow = false;
    let isVersionMismatch = false;

    if (this.pluginSettingsComponent.settings.version && compare(this.pluginVersion, this.pluginSettingsComponent.settings.version) < 0) {
      shouldShow = true;
      isVersionMismatch = true;
      releaseNotes.createEl('h3', { text: t(($) => $.releaseNotes.versionMismatch.title) });
      releaseNotes.append(createFragment((f) => {
        f.appendText(t(($) => $.releaseNotes.versionMismatch.part1));
        f.appendText(' ');
        appendCodeBlock(f, `${this.pluginDir}/data.json`);
        f.appendText(' ');
        f.appendText(t(($) => $.releaseNotes.versionMismatch.part2));
        f.appendText(' ');
        appendCodeBlock(f, this.pluginSettingsComponent.settings.version);
        f.appendText(', ');
        f.appendText(t(($) => $.releaseNotes.versionMismatch.part3));
        f.appendText(' ');
        appendCodeBlock(f, this.pluginVersion);
        f.appendText('. ');
        f.appendText(t(($) => $.releaseNotes.versionMismatch.part4));
      }));
      releaseNotes.createEl('hr');
    }

    for (const [version, versionReleaseNote] of Object.entries(RELEASE_NOTES)) {
      if (!this.pluginSettingsComponent.settings.version || compare(version, this.pluginSettingsComponent.settings.version) <= 0) {
        continue;
      }

      shouldShow = true;
      releaseNotes.createEl('h3', { text: version });
      releaseNotes.append(versionReleaseNote);
      releaseNotes.createEl('hr');
    }

    if (!isVersionMismatch) {
      await this.pluginSettingsComponent.editAndSave((settings) => {
        settings.version = this.pluginVersion;
      });
    }

    if (!shouldShow) {
      return;
    }

    await alert({
      app: this.app,
      message: releaseNotes,
      title: t(($) => $.releaseNotes.title)
    });
  }
}
