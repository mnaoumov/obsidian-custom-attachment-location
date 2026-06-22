import type { ShareReceiver } from '@obsidian-typings/obsidian-public-latest';
import type { App } from 'obsidian';

import { getPrototypeOf } from 'obsidian-dev-utils/object-utils';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import {
  extname,
  makeFileName
} from 'obsidian-dev-utils/path';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { Substitutions } from '../substitutions.ts';
import { ActionContext } from '../token-evaluator-context.ts';
import { TokenValidator } from '../token-validator.ts';

interface ShareReceiverImportFilesPatchComponentConstructorParams {
  readonly app: App;
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly shareReceiver: ShareReceiver;
  readonly tokenValidator: TokenValidator;
}

export const IMPORT_FILES_PREFIX = '__IMPORT_FILES__';

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
      methodName: 'importFiles',
      obj: getPrototypeOf(this.shareReceiver),
      patchHandler: async ({
        fallback,
        originalArgs: [files]
      }) => {
        for (const file of files) {
          const fileUri = window.Capacitor.convertFileSrc(file.uri);
          // eslint-disable-next-line no-restricted-globals, n/no-unsupported-features/node-builtins -- `requestUrl()` doesn't work for those Capacitor urls; fetch is a stable Web API in Obsidian's Electron renderer, the rule incorrectly flags it as a Node experimental builtin.
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
          file.name = IMPORT_FILES_PREFIX + makeFileName(attachmentFileBaseName, attachmentFileExtension);
        }

        return fallback();
      }
    });
  }
}
