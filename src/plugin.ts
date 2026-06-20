import type {
  ClipboardManager,
  ImportedAttachment
} from '@obsidian-typings/obsidian-public-latest';
import type {
  ConfigItem,
  SharedFile,
  ShareReceiver
} from '@obsidian-typings/obsidian-public-latest/implementations';
import type {
  App,
  DataWriteOptions,
  FileManager,
  FileStats,
  WorkspaceLeaf
} from 'obsidian';
import type {
  GetAvailablePathForAttachmentsExtendedFnParams,
  GetAvailablePathForAttachmentsFnExtended
} from 'obsidian-dev-utils/obsidian/attachment-path';
import type { RenameDeleteHandlerSettings } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
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
  getPrototypeOf,
  normalizeOptionalProperties,
  removeUndefinedProperties
} from 'obsidian-dev-utils/object-utils';
import { AppActiveFileProvider } from 'obsidian-dev-utils/obsidian/active-file-provider';
import {
  DUMMY_PATH,
  getAvailablePathForAttachments
} from 'obsidian-dev-utils/obsidian/attachment-path';
import { CommandHandlerComponent } from 'obsidian-dev-utils/obsidian/command-handlers/command-handler-component';
import { PluginCommandRegistrar } from 'obsidian-dev-utils/obsidian/command-registrar';
import { AllWindowsEventComponent } from 'obsidian-dev-utils/obsidian/components/all-windows-event-component';
import { CallbackLayoutReadyComponent } from 'obsidian-dev-utils/obsidian/components/layout-ready-component';
import { MenuEventRegistrarComponent } from 'obsidian-dev-utils/obsidian/components/menu-event-registrar-component';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import { PluginSettingsTabComponent } from 'obsidian-dev-utils/obsidian/components/plugin-settings-tab-component';
import {
  EmptyFolderBehavior,
  RenameDeleteHandlerComponent
} from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import { PluginDataHandler } from 'obsidian-dev-utils/obsidian/data-handler';
import {
  getAbstractFileOrNull,
  getFileOrNull,
  getPath,
  isNote
} from 'obsidian-dev-utils/obsidian/file-system';
import { t, type TranslationsMap } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  encodeUrl,
  extractLinkFile,
  generateMarkdownLink,
  LinkStyle,
  testAngleBrackets,
  testWikilink
} from 'obsidian-dev-utils/obsidian/link';
import {
  getAllLinks,
  getCacheSafe
} from 'obsidian-dev-utils/obsidian/metadata-cache';
import { alert } from 'obsidian-dev-utils/obsidian/modals/alert';
import { PluginBase } from 'obsidian-dev-utils/obsidian/plugin/plugin';
import { PluginEventSourceImpl } from 'obsidian-dev-utils/obsidian/plugin/plugin-event-source';
import { createFolderSafe } from 'obsidian-dev-utils/obsidian/vault';
import {
  basename,
  dirname,
  extname,
  join,
  makeFileName
} from 'obsidian-dev-utils/path';
import { trimStart } from 'obsidian-dev-utils/string';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';
import { compare } from 'semver';

import { isNoteEx } from './attachment-collector.ts';
import {
  getAttachmentFolderFullPathForPath,
  getGeneratedAttachmentFileBaseName
} from './attachment-path.ts';
import { CollectAttachmentsEntireVaultCommandHandler } from './command-handlers/collect-attachments-entire-vault-command-handler.ts';
import { CollectAttachmentsInCurrentFolderCommandHandler } from './command-handlers/collect-attachments-in-current-folder-command-handler.ts';
import { CollectAttachmentsInFileCommandHandler } from './command-handlers/collect-attachments-in-file-command-handler.ts';
import { MoveAttachmentToProperFolderCommandHandler } from './command-handlers/move-attachment-to-proper-folder-command-handler.ts';
import { translationsMap } from './i18n/locales/translations-map.ts';
import {
  getImageSize,
  getMimeType
} from './image.ts';
import { PluginSettingsComponent } from './plugin-settings-component.ts';
import { PluginSettingsTab } from './plugin-settings-tab.ts';
import {
  AttachmentRenameMode,
  ConvertImagesToJpegMode
} from './plugin-settings.ts';
import { PrismComponent } from './prism-component.ts';
import { Substitutions } from './substitutions.ts';
import {
  ActionContext,
  actionContextToAttachmentPathContext,
  attachmentPathContextToActionContext
} from './token-evaluator-context.ts';

const moment = extractDefaultExportInterop(moment_);

type ArrayBufferFn = File['arrayBuffer'];
interface FileEx {
  path: string;
}
type GenerateMarkdownLinkFn = FileManager['generateMarkdownLink'];
type GetAvailablePathFn = Vault['getAvailablePath'];
type GetAvailablePathForAttachmentsFn = Vault['getAvailablePathForAttachments'];
type GetConfigFn = Vault['getConfig'];
type GetPathForFileFn = typeof webUtils['getPathForFile'];
type ImportFilesFn = ShareReceiver['importFiles'];
type InsertFilesFn = ClipboardManager['insertFiles'];

type SaveAttachmentFn = App['saveAttachment'];

const PASTED_IMAGE_NAME_REG_EXP = /Pasted image (?<Timestamp>\d{14})/;
const PASTED_IMAGE_DATE_FORMAT = 'YYYYMMDDHHmmss';
const THRESHOLD_IN_SECONDS = 10;
const IMPORT_FILES_PREFIX = '__IMPORT_FILES__';

interface PluginConvertImageToJpegParams {
  readonly attachmentFileContent: ArrayBuffer;
  readonly attachmentFileExtension: string;
  readonly isPastedImage: boolean;
}

export class Plugin extends PluginBase {
  private readonly arrayBufferFileStatMap = new WeakMap<ArrayBuffer, FileStats>();
  private currentAttachmentFolderPath: null | string = null;
  private readonly getAvailablePathForAttachmentsOriginal: GetAvailablePathForAttachmentsFn | null = null;
  private readonly imageAttachmentSizeMap = new Map<string, string>();
  private isMarkdownViewPatched = false;
  private lastOpenFilePath: null | string = null;
  private readonly pathMarkdownUrlMap = new Map<string, string>();
  private pluginSettingsComponent!: PluginSettingsComponent;

  public override onloadImpl(): void {
    this.pluginSettingsComponent = this.addChild(
      new PluginSettingsComponent({
        dataHandler: new PluginDataHandler(this),
        plugin: this,
        pluginEventSource: new PluginEventSourceImpl(this)
      })
    );

    this.addChild(
      new PluginSettingsTabComponent({
        plugin: this,
        pluginSettingsTab: new PluginSettingsTab({
          plugin: this,
          pluginSettingsComponent: this.pluginSettingsComponent
        })
      })
    );

    this.addChild(new CallbackLayoutReadyComponent(this.app, this.onLayoutReady.bind(this)));
  }

  public async getSequenceNumber(noteFilePath: string, oldAttachmentPathOrFile: PathOrFile): Promise<number> {
    const oldAttachmentFile = getFileOrNull(this.app, oldAttachmentPathOrFile);
    if (!oldAttachmentFile) {
      return 0;
    }

    const cache = await getCacheSafe(this.app, noteFilePath);
    if (!cache) {
      return 0;
    }

    let sequenceNumber = 1;
    for (const link of getAllLinks(cache)) {
      const linkFile = extractLinkFile(this.app, link, noteFilePath);

      if (linkFile === oldAttachmentFile) {
        return sequenceNumber;
      }

      sequenceNumber++;
    }

    return 0;
  }

  public override async onload(): Promise<void> {
    await super.onload();

    this.addChild(
      new RenameDeleteHandlerComponent({
        abortSignalComponent: this.abortSignalComponent,
        app: this.app,
        pluginId: this.manifest.id,
        settingsBuilder: (): Partial<RenameDeleteHandlerSettings> => ({
          emptyFolderBehavior: this.pluginSettingsComponent.settings.emptyFolderBehavior,
          isNote: (path: string): boolean => isNoteEx(this, path, this.pluginSettingsComponent),
          isPathIgnored: (path: string): boolean => this.pluginSettingsComponent.settings.isPathIgnored(path),
          shouldHandleDeletions: this.pluginSettingsComponent.settings.shouldDeleteOrphanAttachments,
          shouldHandleRenames: this.pluginSettingsComponent.settings.shouldHandleRenames,
          shouldRenameAttachmentFiles: this.pluginSettingsComponent.settings.shouldRenameAttachmentFiles,
          shouldRenameAttachmentFolder: this.pluginSettingsComponent.settings.shouldRenameAttachmentFolder,
          shouldUpdateFileNameAliases: true
        })
      })
    );

    const menuEventRegistrar = this.addChild(new MenuEventRegistrarComponent(this.app));
    this.addChild(
      new CommandHandlerComponent({
        activeFileProvider: new AppActiveFileProvider(this.app),
        commandHandlers: [
          new CollectAttachmentsInFileCommandHandler({
            abortSignalComponent: this.abortSignalComponent,
            app: this.app,
            consoleDebugComponent: this.consoleDebugComponent,
            plugin: this,
            pluginSettingsComponent: this.pluginSettingsComponent
          }),
          new CollectAttachmentsInCurrentFolderCommandHandler({
            abortSignalComponent: this.abortSignalComponent,
            consoleDebugComponent: this.consoleDebugComponent,
            plugin: this,
            pluginSettingsComponent: this.pluginSettingsComponent
          }),
          new CollectAttachmentsEntireVaultCommandHandler({
            abortSignalComponent: this.abortSignalComponent,
            consoleDebugComponent: this.consoleDebugComponent,
            plugin: this,
            pluginSettingsComponent: this.pluginSettingsComponent
          }),
          new MoveAttachmentToProperFolderCommandHandler({
            abortSignalComponent: this.abortSignalComponent,
            app: this.app,
            plugin: this,
            pluginSettingsComponent: this.pluginSettingsComponent
          })
        ],
        commandRegistrar: new PluginCommandRegistrar(this),
        menuEventRegistrar,
        pluginName: this.manifest.name
      })
    );

    const patch = this.addChild(new MonkeyAroundComponent());
    patch.registerPatch(this.app, {
      saveAttachment: (): SaveAttachmentFn => {
        return (name, extension, data): Promise<TFile> => {
          return this.saveAttachment(name, extension, data);
        };
      }
    });
    this.addChild(new PrismComponent());

    this.registerEvent(this.app.workspace.on('file-open', convertAsyncToSync(this.handleFileOpen.bind(this))));
    this.registerEvent(this.app.vault.on('rename', convertAsyncToSync(this.handleRename.bind(this))));

    this.registerEvent(this.app.workspace.on('receive-text-menu', this.handleReceiveTextMenu.bind(this)));
    this.registerEvent(this.app.workspace.on('receive-files-menu', this.handleReceiveFilesMenu.bind(this)));
  }

  public replaceSpecialCharacters(str: string): string {
    if (!this.pluginSettingsComponent.settings.specialCharacters) {
      return str;
    }

    str = str.replace(this.pluginSettingsComponent.settings.specialCharactersRegExp, this.pluginSettingsComponent.settings.specialCharactersReplacement);
    return str;
  }

  protected async onLayoutReady(): Promise<void> {
    Substitutions.registerCustomTokens(this.pluginSettingsComponent.settings.customTokensStr);
    await this.pluginSettingsComponent.loadFromFile(false);

    const patch = this.addChild(new MonkeyAroundComponent());
    patch.registerPatch(this.app.vault, {
      getAvailablePath: (): GetAvailablePathFn => this.getAvailablePath.bind(this),
      getAvailablePathForAttachments: (next: GetAvailablePathForAttachmentsFn): GetAvailablePathForAttachmentsFnExtended => {
        const that = this;

        return Object.assign(nextCopy, {
          extended: this.getAvailablePathForAttachments.bind(this)
        });

        function nextCopy(filename: string, extension: string, file: null | TFile): Promise<string> {
          return next.call(that.app.vault, filename, extension, file);
        }
      },
      getConfig: (next: GetConfigFn): GetConfigFn => {
        return (name: ConfigItem): unknown => {
          return this.getConfig(next, name);
        };
      }
    });

    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Actually not available on some platforms.
    if (webUtils) {
      patch.registerPatch(webUtils, {
        getPathForFile: (next: GetPathForFileFn): GetPathForFileFn => {
          return (file: File): string => {
            return this.getPathForFile(file, next);
          };
        }
      });
    }

    patch.registerPatch(this.app.fileManager, {
      generateMarkdownLink: (next: GenerateMarkdownLinkFn): GenerateMarkdownLinkFn => {
        return (file: TFile, sourcePath: string, subpath?: string, alias?: string): string => {
          return this.generateMarkdownLink(next, file, sourcePath, subpath, alias);
        };
      }
    });

    patch.registerPatch(getPrototypeOf(this.app.shareReceiver), {
      importFiles: (next: ImportFilesFn): ImportFilesFn => {
        return (files: SharedFile[]): Promise<void> => {
          return this.importFiles(next, files);
        };
      }
    });

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

  private async fileArrayBuffer(next: ArrayBufferFn, file: File): Promise<ArrayBuffer> {
    const arrayBuffer = await next.call(file);
    if (this.app.vault.adapter instanceof FileSystemAdapter) {
      const path = webUtils.getPathForFile(file);
      if (await this.setFileStat(arrayBuffer, path)) {
        return arrayBuffer;
      }
    }

    this.arrayBufferFileStatMap.set(arrayBuffer, {
      ctime: 0,
      mtime: file.lastModified,
      size: file.size
    });
    return arrayBuffer;
  }

  private generateMarkdownLink(next: GenerateMarkdownLinkFn, file: TFile, sourcePath: string, subpath?: string, alias?: string): string {
    if (alias === undefined) {
      const imageSize = this.imageAttachmentSizeMap.get(file.path);
      if (imageSize) {
        this.imageAttachmentSizeMap.delete(file.path);
        alias = imageSize;
      }
    }
    let defaultLink = next.call(this.app.fileManager, file, sourcePath, subpath, alias);

    if (!this.pluginSettingsComponent.settings.markdownUrlFormat) {
      return defaultLink;
    }

    const markdownUrl = this.pathMarkdownUrlMap.get(file.path);

    if (!markdownUrl) {
      return defaultLink;
    }

    if (testWikilink(defaultLink)) {
      defaultLink = generateMarkdownLink({
        app: this.app,
        linkStyle: LinkStyle.Markdown,
        originalLink: defaultLink,
        sourcePathOrFile: sourcePath,
        targetPathOrFile: file
      });
    }

    if (testAngleBrackets(defaultLink)) {
      return defaultLink.replace(/\]\(<.+?>\)/, `](<${markdownUrl}>)`);
    }

    return defaultLink.replace(/\]\(.+?\)/, `](${encodeUrl(markdownUrl)})`);
  }

  private getAvailablePath(attachmentFileName: string, attachmentExtension: string): string {
    let suffixNum = 0;

    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Easiest infinite loop.
    while (true) {
      const path = makeFileName(
        suffixNum === 0 ? attachmentFileName : `${attachmentFileName}${this.pluginSettingsComponent.settings.duplicateNameSeparator}${String(suffixNum)}`,
        attachmentExtension
      );

      if (!getAbstractFileOrNull(this.app, path, true)) {
        return path;
      }

      suffixNum++;
    }
  }

  private async getAvailablePathForAttachments(params: GetAvailablePathForAttachmentsExtendedFnParams): Promise<string> {
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
      const attachmentFolderFullPath = await getAttachmentFolderFullPathForPath(
        this,
        attachmentPathContextToActionContext(params.context),
        noteFilePath,
        attachmentFileName,
        this.pluginSettingsComponent,
        oldNoteFilePath,
        attachmentFileContent,
        attachmentFileStat
      );
      let generatedAttachmentFileName: string;
      if (shouldSkipGeneratedAttachmentFileName) {
        generatedAttachmentFileName = attachmentFileName;
      } else {
        const cursorLine = await this.getCursorLine(noteFilePath, params.oldAttachmentPathOrFile);
        const sequenceNumber = await this.getSequenceNumber(noteFilePath, params.oldAttachmentPathOrFile);
        const generatedAttachmentFileBaseName = await getGeneratedAttachmentFileBaseName(
          this,
          new Substitutions({
            actionContext: attachmentPathContextToActionContext(params.context),
            attachmentFileContent,
            attachmentFileStat,
            cursorLine,
            noteFilePath,
            oldNoteFilePath,
            originalAttachmentFileName: attachmentFileName,
            plugin: this,
            sequenceNumber
          }),
          this.pluginSettingsComponent
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

  private getConfig(next: GetConfigFn, name: ConfigItem): unknown {
    if (name !== 'attachmentFolderPath' || this.currentAttachmentFolderPath === null) {
      return next.call(this.app.vault, name);
    }

    return this.currentAttachmentFolderPath;
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

  private getPathForFile(file: File, next: GetPathForFileFn): string {
    const fileEx = file as Partial<FileEx>;
    if (fileEx.path) {
      return fileEx.path;
    }
    return next(file);
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

    const that = this;
    const patch = this.addChild(new MonkeyAroundComponent());
    patch.registerPatch(getPrototypeOf(markdownView.editMode.clipboardManager), {
      insertFiles: (next: InsertFilesFn): InsertFilesFn => {
        return function insertFilesPatched(this: ClipboardManager, importedAttachments: ImportedAttachment[]): Promise<void> {
          return that.insertFiles(next, this, importedAttachments);
        };
      }
    });

    this.isMarkdownViewPatched = true;
  }

  private async handleFileOpen(file: null | TFile): Promise<void> {
    if (file === null || this.pluginSettingsComponent.settings.isPathIgnored(file.path)) {
      this.currentAttachmentFolderPath = null;
      this.lastOpenFilePath = null;
      return;
    }

    if (file.path === this.lastOpenFilePath) {
      return;
    }

    this.lastOpenFilePath = file.path;
    this.currentAttachmentFolderPath = await getAttachmentFolderFullPathForPath(
      this,
      ActionContext.OpenFile,
      file.path,
      DUMMY_PATH,
      this.pluginSettingsComponent
    );
  }

  private handleInputFileChange(evt: Event): void {
    if (!(evt.target instanceof HTMLInputElement)) {
      return;
    }

    if (evt.target.type !== 'file') {
      return;
    }

    const that = this;
    for (const file of evt.target.files ?? []) {
      const patch = this.addChild(new MonkeyAroundComponent());
      patch.registerPatch(file, {
        arrayBuffer: (next: ArrayBufferFn): ArrayBufferFn => {
          return function arrayBufferPatched(this: File): Promise<ArrayBuffer> {
            return that.fileArrayBuffer(next, this);
          };
        }
      });
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

  private async importFiles(next: ImportFilesFn, files: SharedFile[]): Promise<void> {
    for (const file of files) {
      const fileUri = window.Capacitor.convertFileSrc(file.uri);
      // eslint-disable-next-line no-restricted-globals, n/no-unsupported-features/node-builtins -- `requestUrl()` doesn't work for those Capacitor urls; fetch is a stable Web API in Obsidian's Electron renderer, the rule incorrectly flags it as a Node experimental builtin.
      const response = await fetch(fileUri);
      const attachmentFileContent = await response.arrayBuffer();
      const substitutions = new Substitutions({
        actionContext: ActionContext.ImportFiles,
        attachmentFileContent,
        noteFilePath: this.app.workspace.getActiveFile()?.path ?? '',
        originalAttachmentFileName: file.name,
        plugin: this
      });
      const attachmentFileBaseName = await getGeneratedAttachmentFileBaseName(this, substitutions, this.pluginSettingsComponent);
      const attachmentFileExtension = extname(file.name).slice(1);
      file.name = IMPORT_FILES_PREFIX + makeFileName(attachmentFileBaseName, attachmentFileExtension);
    }

    return next.call(this.app.shareReceiver, files);
  }

  private async insertFiles(next: InsertFilesFn, clipboardManager: ClipboardManager, importedAttachments: ImportedAttachment[]): Promise<void> {
    for (const importedAttachment of importedAttachments) {
      const arrayBuffer = await importedAttachment.data;
      await this.setFileStat(arrayBuffer, importedAttachment.filepath);
    }
    return next.call(clipboardManager, importedAttachments);
  }

  private async saveAttachment(
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
      attachmentFileBaseName = await getGeneratedAttachmentFileBaseName(
        this,
        new Substitutions({
          actionContext: ActionContext.SaveAttachment,
          attachmentFileContent,
          attachmentFileStat: this.arrayBufferFileStatMap.get(attachmentFileContent),
          noteFilePath: activeNoteFile.path,
          originalAttachmentFileName: makeFileName(attachmentFileBaseName, attachmentFileExtension),
          plugin: this
        }),
        this.pluginSettingsComponent
      );
    }

    const attachmentFile = await this.saveAttachmentCore(attachmentFileBaseName, attachmentFileExtension, attachmentFileContent);
    if (this.pluginSettingsComponent.settings.markdownUrlFormat) {
      const markdownUrl = await new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        attachmentFileContent,
        attachmentFileStat: this.arrayBufferFileStatMap.get(attachmentFileContent),
        generatedAttachmentFileName: attachmentFile.name,
        generatedAttachmentFilePath: attachmentFile.path,
        noteFilePath: activeNoteFile.path,
        originalAttachmentFileName: makeFileName(attachmentFileBaseName, attachmentFileExtension),
        plugin: this
      }).fillTemplate(this.pluginSettingsComponent.settings.markdownUrlFormat);
      this.pathMarkdownUrlMap.set(attachmentFile.path, markdownUrl);
    } else {
      this.pathMarkdownUrlMap.delete(attachmentFile.path);
    }
    return attachmentFile;
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

  private async setFileStat(arrayBuffer: ArrayBuffer, filePath: string): Promise<boolean> {
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

    if (this.pluginSettingsComponent.settings.version && compare(this.manifest.version, this.pluginSettingsComponent.settings.version) < 0) {
      shouldShow = true;
      isVersionMismatch = true;
      releaseNotes.createEl('h3', { text: t(($) => $.releaseNotes.versionMismatch.title) });
      releaseNotes.append(createFragment((f) => {
        f.appendText(t(($) => $.releaseNotes.versionMismatch.part1));
        f.appendText(' ');
        appendCodeBlock(f, `${this.manifest.dir ?? ''}/data.json`);
        f.appendText(' ');
        f.appendText(t(($) => $.releaseNotes.versionMismatch.part2));
        f.appendText(' ');
        appendCodeBlock(f, this.pluginSettingsComponent.settings.version);
        f.appendText(', ');
        f.appendText(t(($) => $.releaseNotes.versionMismatch.part3));
        f.appendText(' ');
        appendCodeBlock(f, this.manifest.version);
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
        settings.version = this.manifest.version;
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

  protected override createTranslationsMap(): TranslationsMap {
    return translationsMap;
  }
}
