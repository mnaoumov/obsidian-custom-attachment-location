import type {
  App,
  DataWriteOptions,
  FileStats,
  WorkspaceLeaf
} from 'obsidian';
import type { GetAvailablePathForAttachmentsExtendedFnParams } from 'obsidian-dev-utils/obsidian/attachment-path';
import type { PathOrFile } from 'obsidian-dev-utils/obsidian/file-system';

import {
  isReferenceCache,
  parentFolderPath,
  ViewType
} from '@obsidian-typings/obsidian-public-latest/implementations';
import { webUtils } from 'electron';
import {
  CapacitorAdapter,
  FileSystemAdapter,
  MarkdownView,
  Menu,
  MenuItem,
  moment as moment_,
  TFile,
  Vault
} from 'obsidian';
import { convertAsyncToSync } from 'obsidian-dev-utils/async';
import { blobToJpegArrayBuffer } from 'obsidian-dev-utils/blob';
import { appendCodeBlock } from 'obsidian-dev-utils/html-element';
import {
  extractDefaultExportInterop,
  normalizeOptionalProperties,
  removeUndefinedProperties
} from 'obsidian-dev-utils/object-utils';
import {
  DUMMY_PATH,
  getAvailablePathForAttachments
} from 'obsidian-dev-utils/obsidian/attachment-path';
import { AllWindowsEventComponent } from 'obsidian-dev-utils/obsidian/components/all-windows-event-component';
import { LayoutReadyComponent } from 'obsidian-dev-utils/obsidian/components/layout-ready-component';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import {
  getFileOrNull,
  getPath,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { extractLinkFile } from 'obsidian-dev-utils/obsidian/link';
import {
  getAllLinks,
  getCacheSafe
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { alert } from 'obsidian-dev-utils/obsidian/modals/alert';
import { createFolderSafe } from 'obsidian-dev-utils/obsidian/vault';
import {
  basename,
  dirname,
  join,
  makeFileName
} from 'obsidian-dev-utils/path';
import { trimStart } from 'obsidian-dev-utils/string';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';
import { compare } from 'semver';

import type { AttachmentPathManager } from './attachment-path-manager.ts';

import {
  getImageSize,
  getMimeType
} from './image.ts';
import { ClipboardManagerInsertFilesPatchComponent } from './patches/clipboard-manager-insert-files-patch-component.ts';
import { FileArrayBufferPatchComponent } from './patches/file-array-buffer-patch-component.ts';
import { FileManagerGenerateMarkdownLinkPatchComponent } from './patches/file-manager-generate-markdown-link-patch-component.ts';
import {
  IMPORT_FILES_PREFIX,
  ShareReceiverImportFilesPatchComponent
} from './patches/share-receiver-import-files-patch-component.ts';
import { VaultGetAvailablePathForAttachmentsPatchComponent } from './patches/vault-get-available-path-for-attachments-patch-component.ts';
import { VaultGetAvailablePathPatchComponent } from './patches/vault-get-available-path-patch-component.ts';
import { VaultGetConfigPatchComponent } from './patches/vault-get-config-patch-component.ts';
import { WebUtilsGetPathForFilePatchComponent } from './patches/web-utils-get-path-for-file-patch-component.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import {
  AttachmentRenameMode,
  ConvertImagesToJpegMode
} from './plugin-settings.ts';
import { Substitutions } from './substitutions.ts';
import {
  ActionContext,
  actionContextToAttachmentPathContext,
  attachmentPathContextToActionContext
} from './token-evaluator-context.ts';

const moment = extractDefaultExportInterop(moment_);

type GetAvailablePathForAttachmentsFn = Vault['getAvailablePathForAttachments'];

const PASTED_IMAGE_NAME_REG_EXP = /Pasted image (?<Timestamp>\d{14})/;
const PASTED_IMAGE_DATE_FORMAT = 'YYYYMMDDHHmmss';
const THRESHOLD_IN_SECONDS = 10;

interface CustomAttachmentLocationComponentConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginDir: string;
  readonly pluginName: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly pluginVersion: string;
}

interface CustomAttachmentLocationComponentGetAvailablePathForAttachmentsParams extends GetAvailablePathForAttachmentsExtendedFnParams {
  readonly __brand?: 'CustomAttachmentLocationComponentGetAvailablePathForAttachmentsParams';
}

interface PluginConvertImageToJpegParams {
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
  readonly isPastedImage: boolean;
}

export class CustomAttachmentLocationComponent extends LayoutReadyComponent {
  public readonly arrayBufferFileStatMap = new WeakMap<ArrayBuffer, FileStats>();
  public readonly imageAttachmentSizeMap = new Map<string, string>();
  public pathMarkdownUrlMap = new Map<string, string>();
  public readonly pluginDir: string;

  public readonly pluginName: string;

  public readonly pluginVersion: string;

  public get currentAttachmentFolderPath(): null | string {
    return this._currentAttachmentFolderPath;
  }

  private _currentAttachmentFolderPath: null | string = null;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFn | null = null;
  private isMarkdownViewPatched = false;
  private lastOpenFilePath: null | string = null;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: CustomAttachmentLocationComponentConstructorParams) {
    super(params.app);
    this.pluginName = params.pluginName;
    this.pluginVersion = params.pluginVersion;
    this.pluginDir = params.pluginDir;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.attachmentPathManager = params.attachmentPathManager;
  }

  public async getAvailablePathForAttachments(params: CustomAttachmentLocationComponentGetAvailablePathForAttachmentsParams): Promise<string> {
    const {
      attachmentFileExtension,
      notePathOrFile,
      shouldSkipDuplicateCheck,
      shouldSkipMissingAttachmentFolderCreation
    } = params;
    let {
      attachmentFileBaseName,
      attachmentFileContent,
      attachmentFileStat,
      shouldSkipGeneratedAttachmentFileName
    } = params;

    if (attachmentFileBaseName === DUMMY_PATH) {
      attachmentFileContent ??= new ArrayBuffer(0);
      const now = Math.trunc(Date.now());
      attachmentFileStat ??= {
        ctime: now,
        mtime: now,
        size: 0
      };
    }

    const noteFile = getFileOrNull(this.app, notePathOrFile);
    const noteFilePath = notePathOrFile ? getPath(this.app, notePathOrFile) : undefined;
    const oldNoteFilePath = params.oldNotePathOrFile ? getPath(this.app, params.oldNotePathOrFile) : undefined;

    if (attachmentFileBaseName.startsWith(IMPORT_FILES_PREFIX)) {
      attachmentFileBaseName = trimStart(attachmentFileBaseName, IMPORT_FILES_PREFIX);
      shouldSkipGeneratedAttachmentFileName = true;
    }
    if (noteFile && this.pluginSettingsComponent.settings.isPathIgnored(noteFile.path) && this.getAvailablePathForAttachmentsOriginal) {
      return this.getAvailablePathForAttachmentsOriginal(attachmentFileBaseName, attachmentFileExtension, noteFile);
    }

    let attachmentPath: string;
    if (!noteFilePath || !isNote(this.app, noteFilePath)) {
      attachmentPath = await getAvailablePathForAttachments({
        app: this.app,
        attachmentFileBaseName,
        attachmentFileExtension,
        notePathOrFile,
        shouldSkipDuplicateCheck: shouldSkipDuplicateCheck ?? false,
        shouldSkipMissingAttachmentFolderCreation: shouldSkipMissingAttachmentFolderCreation ?? true
      });
    } else {
      const attachmentFileName = makeFileName(attachmentFileBaseName, attachmentFileExtension);
      const attachmentFolderFullPath = await this.attachmentPathManager.getAttachmentFolderFullPathForPath({
        actionContext: attachmentPathContextToActionContext(params.context),
        attachmentFileContent,
        attachmentFileName,
        attachmentFileStat,
        notePath: noteFilePath,
        oldNoteFilePath
      });
      let generatedAttachmentFileName: string;
      if (shouldSkipGeneratedAttachmentFileName) {
        generatedAttachmentFileName = attachmentFileName;
      } else {
        const cursorLine = await this.getCursorLine(noteFilePath, params.oldAttachmentPathOrFile);
        const sequenceNumber = await this.attachmentPathManager.getSequenceNumber(noteFilePath, params.oldAttachmentPathOrFile);
        const generatedAttachmentFileBaseName = await this.attachmentPathManager.getGeneratedAttachmentFileBaseName(
          new Substitutions({
            actionContext: attachmentPathContextToActionContext(params.context),
            app: this.app,
            attachmentFileContent,
            attachmentFileStat,
            cursorLine,
            noteFilePath,
            oldNoteFilePath,
            originalAttachmentFileName: attachmentFileName,
            pluginSettingsComponent: this.pluginSettingsComponent,
            sequenceNumber
          })
        );
        generatedAttachmentFileName = makeFileName(generatedAttachmentFileBaseName, attachmentFileExtension);
      }
      const generatedAttachmentFileNamePath = join(attachmentFolderFullPath, generatedAttachmentFileName);
      if (shouldSkipDuplicateCheck) {
        attachmentPath = generatedAttachmentFileNamePath;
      } else {
        const dir = dirname(generatedAttachmentFileNamePath);
        const generatedAttachmentFileNameBaseName = basename(generatedAttachmentFileNamePath, attachmentFileExtension ? `.${attachmentFileExtension}` : '');
        attachmentPath = this.app.vault.getAvailablePath(join(dir, generatedAttachmentFileNameBaseName), attachmentFileExtension);
      }
    }

    if (!shouldSkipMissingAttachmentFolderCreation) {
      const folderPath = parentFolderPath(attachmentPath);
      if (!await this.app.vault.exists(folderPath)) {
        await createFolderSafe(this.app, folderPath);
        if (this.pluginSettingsComponent.settings.emptyFolderBehavior === EmptyFolderBehavior.Keep) {
          await this.app.vault.create(join(folderPath, '.gitkeep'), '');
        }
      }
    }

    return attachmentPath;
  }

  public override onload(): void {
    super.onload();
    this.registerEvent(this.app.workspace.on('file-open', convertAsyncToSync(this.handleFileOpen.bind(this))));
    this.registerEvent(this.app.vault.on('rename', convertAsyncToSync(this.handleRename.bind(this))));

    this.registerEvent(this.app.workspace.on('receive-text-menu', this.handleReceiveTextMenu.bind(this)));
    this.registerEvent(this.app.workspace.on('receive-files-menu', this.handleReceiveFilesMenu.bind(this)));
  }

  public async saveAttachment(
    attachmentFileBaseName: string,
    attachmentFileExtension: string,
    attachmentFileContent: ArrayBuffer
  ): Promise<TFile> {
    const activeNoteFile = this.app.workspace.getActiveFile();
    if (!activeNoteFile || this.pluginSettingsComponent.settings.isPathIgnored(activeNoteFile.path)) {
      return await this.saveAttachmentCore(attachmentFileBaseName, attachmentFileExtension, attachmentFileContent);
    }

    let isPastedImage = false;
    const match = PASTED_IMAGE_NAME_REG_EXP.exec(attachmentFileBaseName);
    if (match) {
      const timestampString = ensureNonNullable(match.groups?.['Timestamp']);
      const parsedDate = moment(timestampString, PASTED_IMAGE_DATE_FORMAT);
      if (parsedDate.isValid()) {
        if (moment().diff(parsedDate, 'seconds') < THRESHOLD_IN_SECONDS) {
          isPastedImage = true;
        }
      }
    }

    let convertImageToJpegOptions: PluginConvertImageToJpegParams = {
      attachmentFileContent,
      attachmentFileExtension,
      isPastedImage
    };
    convertImageToJpegOptions = await this.convertImageToJpeg(convertImageToJpegOptions);
    attachmentFileExtension = convertImageToJpegOptions.attachmentFileExtension;
    attachmentFileContent = convertImageToJpegOptions.attachmentFileContent;

    let shouldRename = false;

    switch (this.pluginSettingsComponent.settings.attachmentRenameMode) {
      case AttachmentRenameMode.All:
        shouldRename = true;
        break;
      case AttachmentRenameMode.None:
        break;
      case AttachmentRenameMode.OnlyPastedImages:
        shouldRename = isPastedImage;
        break;
      default:
        throw new Error('Invalid attachment rename mode');
    }

    if (shouldRename) {
      attachmentFileBaseName = await this.attachmentPathManager.getGeneratedAttachmentFileBaseName(
        new Substitutions({
          actionContext: ActionContext.SaveAttachment,
          app: this.app,
          attachmentFileContent,
          attachmentFileStat: this.arrayBufferFileStatMap.get(attachmentFileContent),
          noteFilePath: activeNoteFile.path,
          originalAttachmentFileName: makeFileName(attachmentFileBaseName, attachmentFileExtension),
          pluginSettingsComponent: this.pluginSettingsComponent
        })
      );
    }

    const attachmentFile = await this.saveAttachmentCore(attachmentFileBaseName, attachmentFileExtension, attachmentFileContent);
    if (this.pluginSettingsComponent.settings.markdownUrlFormat) {
      const markdownUrl = await new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        app: this.app,
        attachmentFileContent,
        attachmentFileStat: this.arrayBufferFileStatMap.get(attachmentFileContent),
        generatedAttachmentFileName: attachmentFile.name,
        generatedAttachmentFilePath: attachmentFile.path,
        noteFilePath: activeNoteFile.path,
        originalAttachmentFileName: makeFileName(attachmentFileBaseName, attachmentFileExtension),
        pluginSettingsComponent: this.pluginSettingsComponent
      }).fillTemplate(this.pluginSettingsComponent.settings.markdownUrlFormat);
      this.pathMarkdownUrlMap.set(attachmentFile.path, markdownUrl);
    } else {
      this.pathMarkdownUrlMap.delete(attachmentFile.path);
    }
    return attachmentFile;
  }

  public async setFileStat(arrayBuffer: ArrayBuffer, filePath: string): Promise<boolean> {
    if (!filePath) {
      return false;
    }

    if (this.app.vault.adapter instanceof FileSystemAdapter) {
      const stats = await this.app.vault.adapter.fsPromises.stat(filePath);
      this.arrayBufferFileStatMap.set(arrayBuffer, {
        ctime: stats.ctimeMs,
        mtime: stats.mtimeMs,
        size: stats.size
      });
      return true;
    }

    if (this.app.vault.adapter instanceof CapacitorAdapter) {
      const stats = await this.app.vault.adapter.fs.stat(filePath);
      this.arrayBufferFileStatMap.set(arrayBuffer, {
        ctime: stats.ctime ?? 0,
        mtime: stats.mtime ?? 0,
        size: arrayBuffer.byteLength
      });
      return true;
    }

    return false;
  }

  protected override async onLayoutReady(): Promise<void> {
    Substitutions.registerCustomTokens(this.pluginSettingsComponent.settings.customTokensStr);
    await this.pluginSettingsComponent.loadFromFile(false);

    this.addChild(
      new VaultGetAvailablePathForAttachmentsPatchComponent({
        customAttachmentLocationComponent: this,
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
        customAttachmentLocationComponent: this,
        fileManager: this.app.fileManager,
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

  private async convertImageToJpeg(params: PluginConvertImageToJpegParams): Promise<PluginConvertImageToJpegParams> {
    const mimeType = getMimeType(params.attachmentFileExtension);
    let shouldConvertImageToJpeg = false;

    if (mimeType) {
      switch (this.pluginSettingsComponent.settings.convertImagesToJpegMode) {
        case ConvertImagesToJpegMode.AllImages:
          shouldConvertImageToJpeg = true;
          break;
        case ConvertImagesToJpegMode.AllImagesExceptAlreadyJpegFiles:
          if (mimeType !== 'image/jpeg') {
            shouldConvertImageToJpeg = true;
          }
          break;
        case ConvertImagesToJpegMode.None:
          break;
        case ConvertImagesToJpegMode.OnlyPastedClipboardPngImages:
          if (params.isPastedImage && mimeType === 'image/png') {
            shouldConvertImageToJpeg = true;
          }
          break;
        default:
          throw new Error(`Invalid convert images to JPEG mode: ${this.pluginSettingsComponent.settings.convertImagesToJpegMode as string}`);
      }
    }

    if (shouldConvertImageToJpeg && mimeType) {
      return {
        ...params,
        attachmentFileContent: await blobToJpegArrayBuffer(
          new Blob([params.attachmentFileContent], { type: mimeType }),
          this.pluginSettingsComponent.settings.jpegQuality
        ),
        attachmentFileExtension: 'jpg'
      };
    }

    return params;
  }

  private async getCursorLine(noteFilePath: string, oldAttachmentPathOrFile: PathOrFile): Promise<number> {
    const oldAttachmentFile = getFileOrNull(this.app, oldAttachmentPathOrFile);
    if (!oldAttachmentFile) {
      return 0;
    }

    const cache = await getCacheSafe(this.app, noteFilePath);
    if (!cache) {
      return 0;
    }

    for (const link of getAllLinks(cache)) {
      if (!isReferenceCache(link)) {
        continue;
      }

      const linkFile = extractLinkFile(this.app, link, noteFilePath);
      if (!linkFile) {
        continue;
      }

      if (linkFile === oldAttachmentFile) {
        return link.position.start.line;
      }
    }

    return 0;
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
        clipboardManager: markdownView.editMode.clipboardManager,
        customAttachmentLocationComponent: this
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
          customAttachmentLocationComponent: this,
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

  private async saveAttachmentCore(
    attachmentFileBaseName: string,
    attachmentFileExtension: string,
    attachmentFileContent: ArrayBuffer
  ): Promise<TFile> {
    const noteFile = this.app.workspace.getActiveFile();
    const attachmentFileStat = this.arrayBufferFileStatMap.get(attachmentFileContent);

    const attachmentPath = await this.getAvailablePathForAttachments({
      attachmentFileBaseName,
      attachmentFileContent,
      attachmentFileExtension,
      attachmentFileStat,
      context: actionContextToAttachmentPathContext(ActionContext.SaveAttachment),
      notePathOrFile: noteFile,
      oldAttachmentPathOrFile: makeFileName(attachmentFileBaseName, attachmentFileExtension),
      shouldSkipDuplicateCheck: false,
      shouldSkipGeneratedAttachmentFileName: true,
      shouldSkipMissingAttachmentFolderCreation: false
    });

    const imageSize = await getImageSize(attachmentFileExtension, attachmentFileContent, this.pluginSettingsComponent);
    if (imageSize !== null) {
      this.imageAttachmentSizeMap.set(attachmentPath, imageSize);
    }

    return await this.app.vault.createBinary(
      attachmentPath,
      attachmentFileContent,
      removeUndefinedProperties(normalizeOptionalProperties<DataWriteOptions>({
        ctime: attachmentFileStat?.ctime ? Math.trunc(attachmentFileStat.ctime) : undefined,
        mtime: attachmentFileStat?.mtime ? Math.trunc(attachmentFileStat.mtime) : undefined
      }))
    );
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
