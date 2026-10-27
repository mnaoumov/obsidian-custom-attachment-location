import type { ShareReceiver } from '@obsidian-typings/obsidian-public-latest';
import type { App } from 'obsidian';

import { MonkeyAroundComponent } from '@mnaoumov/obsidian-lib/components/monkey-around-component';
import { getPrototypeOf } from '@mnaoumov/typescript-lib/object-utils';
import {
  extname,
  makeFileName
} from '@mnaoumov/typescript-lib/path';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';

import { Substitutions } from '../tokens/substitutions.ts';
import { ActionContext } from '../tokens/token-evaluator-context.ts';
import { TokenValidator } from '../tokens/token-validator.ts';

interface ShareReceiverImportFilesPatchComponentConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly shareReceiver: ShareReceiver;
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
  private readonly tokenValidator: TokenValidator;

  public constructor(params: ShareReceiverImportFilesPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.attachmentPathManager = params.attachmentPathManager;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.shareReceiver = params.shareReceiver;
    this.tokenValidator = params.tokenValidator;
  }

  public override onload(): void {
    this.registerMethodPatch({
      $object: getPrototypeOf(this.shareReceiver),
      methodName: 'importFiles',
      patchHandler: async ({
        fallback,
        originalArguments: [files]
      }) => {
        for (const file of files) {
          const fileUri = window.Capacitor.convertFileSrc(file.uri);
          // eslint-disable-next-line n/no-unsupported-features/node-builtins -- this is executed on mobile only, not in Node.
          const fetch = window.fetch.bind(window);
          const response = await fetch(fileUri);
          const attachmentFileContent = await response.arrayBuffer();
          const substitutions = new Substitutions({
            actionContext: ActionContext.ImportFiles,
            app: this.app,
            attachmentFileContent,
            noteFilePath: this.app.workspace.getActiveFile()?.path ?? '',
            originalAttachmentFileName: file.name,
            pluginSettingsComponent: this.pluginSettingsComponent,
            tokenValidator: this.tokenValidator
          });
          const attachmentFileBaseName = await this.attachmentPathManager.getGeneratedAttachmentFileBaseName(substitutions);
          const attachmentFileExtension = extname(file.name).slice(1);
          const generatedFileName = makeFileName({
            fileBaseName: attachmentFileBaseName,
            fileExtension: attachmentFileExtension
          });
          rememberShareImportOriginalFileName(generatedFileName, file.name);
          file.name = IMPORT_FILES_PREFIX + generatedFileName;
        }

        return fallback();
      }
    });
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
