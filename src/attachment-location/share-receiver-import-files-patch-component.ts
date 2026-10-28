import type {
  SharedFile,
  ShareReceiver
} from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  TFile
} from 'obsidian';

import { MonkeyAroundComponent } from '@mnaoumov/obsidian-lib/components/monkey-around-component';
import { getAbstractFileOrNull } from '@mnaoumov/obsidian-lib/file-system';
import { getPrototypeOf } from '@mnaoumov/typescript-lib/object-utils';
import {
  basename,
  dirname,
  extname,
  join,
  makeFileName
} from '@mnaoumov/typescript-lib/path';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { SidecarAttachmentsComponent } from '../sidecars/sidecar-attachments-component.ts';
import type { SidecarBase } from '../sidecars/sidecar-matcher.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';

import { getSidecarPath } from '../sidecars/sidecar-matcher.ts';
import { Substitutions } from '../tokens/substitutions.ts';
import { ActionContext } from '../tokens/token-evaluator-context.ts';
import { TokenValidator } from '../tokens/token-validator.ts';

interface ShareBatch {
  readonly files: readonly SharedFile[];
  readonly names: readonly string[];
  readonly note: null | TFile;
  readonly pairings: readonly (null | SidecarBase | undefined)[];
  readonly rootNames: (string | undefined)[];
}

interface ShareReceiverImportFilesPatchComponentConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly shareReceiver: ShareReceiver;
  readonly sidecarAttachmentsComponent?: SidecarAttachmentsComponent;
  readonly tokenValidator: TokenValidator;
}

export const IMPORT_FILES_PREFIX = '__IMPORT_FILES__';

/**
 * How many shared files' original names are kept. A share sheet hands over a handful at a time, so this only bounds
 * what a long session could otherwise accumulate.
 */
const MAX_SHARE_IMPORT_ORIGINAL_FILE_NAMES = 100;

/**
 * The name each shared file arrived with, keyed by the name this patch generated for it. The import renames the
 * file before it reaches the resolver, which would otherwise see only the generated name.
 */
const shareImportOriginalFileNames = new Map<string, string>();

export class ShareReceiverImportFilesPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly shareReceiver: ShareReceiver;
  private readonly sidecarAttachmentsComponent: SidecarAttachmentsComponent | undefined;
  private readonly tokenValidator: TokenValidator;

  public constructor(params: ShareReceiverImportFilesPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.shareReceiver = params.shareReceiver;
    this.sidecarAttachmentsComponent = params.sidecarAttachmentsComponent;
    this.tokenValidator = params.tokenValidator;
  }

  public override onload(): void {
    this.registerMethodPatch({
      $object: getPrototypeOf(this.shareReceiver),
      methodName: 'importFiles',
      patchHandler: async ({
        fallback,
        originalArguments: [sharedFiles]
      }) => {
        // Core saves a shared note through `getAvailablePath`, which never strips the prefix, so a note keeps core's behavior.
        const files = sharedFiles.filter((file) => !isSavedAsNote(file));
        const names = files.map((file) => file.name);
        const note = this.app.workspace.getActiveFile();
        const pairings = names.map((name) => this.sidecarAttachmentsComponent?.findBase(name, names));
        const rootNames: (string | undefined)[] = [];

        // Only a base or an orphan is named on its own; a companion takes its base's generated name.
        for (const [index, file] of files.entries()) {
          const pairing = pairings[index];
          if (pairing === null) {
            this.sidecarAttachmentsComponent?.reportUnpaired(file.name);
            rootNames.push(file.name);
          } else if (pairing === undefined) {
            rootNames.push(await this.generateFileName(file, note));
          } else {
            rootNames.push(undefined);
          }
        }

        const batch: ShareBatch = { files, names, note, pairings, rootNames };

        if (batch.pairings.some((pairing) => pairing !== undefined)) {
          await this.reserveGroupNames(batch);
        }

        const generatedFileNames = files.map((_, index) => getFileName(batch, index));
        for (const [index, file] of files.entries()) {
          const generatedFileName = ensureNonNullable(generatedFileNames[index]);
          rememberShareImportOriginalFileName(generatedFileName, file.name);
          file.name = IMPORT_FILES_PREFIX + generatedFileName;
        }

        return fallback();
      }
    });
  }

  private async generateFileName(file: SharedFile, note: null | TFile): Promise<string> {
    const fileUri = window.Capacitor.convertFileSrc(file.uri);
    // eslint-disable-next-line n/no-unsupported-features/node-builtins -- this is executed on mobile only, not in Node.
    const fetch = window.fetch.bind(window);
    const response = await fetch(fileUri);
    const attachmentFileContent = await response.arrayBuffer();
    const substitutions = new Substitutions({
      actionContext: ActionContext.ImportFiles,
      app: this.app,
      attachmentFileContent,
      noteFilePath: note?.path ?? '',
      originalAttachmentFileName: file.name,
      pluginSettingsComponent: this.pluginSettingsComponent,
      tokenValidator: this.tokenValidator
    });
    const attachmentFileBaseName = await this.attachmentPathManager.getGeneratedAttachmentFileBaseName(substitutions);
    return makeFileName({
      fileBaseName: attachmentFileBaseName,
      fileExtension: extname(file.name).slice(1)
    });
  }

  /**
   * Core saves each shared file in turn and suffixes a taken name on its own, which would give a base `doc 1.html`
   * and leave its companion at `doc.html.p7s`. So every root in a batch with sidecars claims, before the first save,
   * the first suffix under which it and all its companions are free, both in the vault and among earlier roots.
   *
   * @param batch - The batch whose root names are replaced by the reserved ones.
   */
  private async reserveGroupNames(batch: ShareBatch): Promise<void> {
    const reservedPaths = new Set<string>();
    const separator = this.pluginSettingsComponent.settings.duplicateNameSeparator;
    for (const [rootIndex, rootName] of batch.rootNames.entries()) {
      if (rootName === undefined) {
        continue;
      }
      const extension = extname(rootName);
      const stem = basename(rootName, extension);
      // The same resolution core is about to make for this file, so the folder is the one it will save into.
      const probedPath = await this.app.vault.getAvailablePathForAttachments(IMPORT_FILES_PREFIX + stem, extension.slice(1), batch.note);
      const folder = dirname(probedPath);
      const groupIndices = batch.files.map((_, index) => index).filter((index) => getRootIndex(batch, index) === rootIndex);
      for (let suffixNumber = 0;; suffixNumber++) {
        batch.rootNames[rootIndex] = suffixNumber === 0 ? rootName : stem + separator + String(suffixNumber) + extension;
        const paths = groupIndices.map((index) => join(folder, getFileName(batch, index)));
        const isFree = paths.every((path) => !reservedPaths.has(path.toLowerCase()) && !getAbstractFileOrNull({ app: this.app, isCaseInsensitive: true, pathOrFile: path }));
        if (isFree) {
          for (const path of paths) {
            reservedPaths.add(path.toLowerCase());
          }
          break;
        }
      }
    }
  }
}

/**
 * The name a shared file arrived with.
 *
 * @param generatedFileName - The name this patch generated for it, extension included.
 * @returns The name it arrived with, or `undefined` when the file did not come through the share sheet.
 */
export function getShareImportOriginalFileName(generatedFileName: string): string | undefined {
  return shareImportOriginalFileNames.get(generatedFileName);
}

function getBaseIndex(batch: ShareBatch, index: number): number | undefined {
  const pairing = batch.pairings[index];
  // The matcher pairs only with a name that occurs once in the batch.
  return pairing ? batch.names.indexOf(pairing.baseName) : undefined;
}

function getFileName(batch: ShareBatch, index: number): string {
  const baseIndex = getBaseIndex(batch, index);
  // A chained signature such as `document.html.p7s.asc` follows `document.html.p7s`, which follows `document.html`.
  return baseIndex === undefined
    ? ensureNonNullable(batch.rootNames[index])
    : getSidecarPath(getFileName(batch, baseIndex), ensureNonNullable(batch.pairings[index]));
}

function getRootIndex(batch: ShareBatch, index: number): number {
  const baseIndex = getBaseIndex(batch, index);
  return baseIndex === undefined ? index : getRootIndex(batch, baseIndex);
}

/**
 * Whether core saves a shared file as a note rather than as an attachment. Core compares the lowercased extension.
 *
 * @param file - The shared file.
 * @returns `true` when core sends it to `getAvailablePath` instead of `getAvailablePathForAttachments`.
 */
function isSavedAsNote(file: SharedFile): boolean {
  return extname(file.name).slice(1).toLowerCase() === 'md';
}

function rememberShareImportOriginalFileName(generatedFileName: string, originalFileName: string): void {
  shareImportOriginalFileNames.delete(generatedFileName);
  shareImportOriginalFileNames.set(generatedFileName, originalFileName);
  for (const oldestGeneratedFileName of shareImportOriginalFileNames.keys()) {
    if (shareImportOriginalFileNames.size <= MAX_SHARE_IMPORT_ORIGINAL_FILE_NAMES) {
      break;
    }
    shareImportOriginalFileNames.delete(oldestGeneratedFileName);
  }
}
