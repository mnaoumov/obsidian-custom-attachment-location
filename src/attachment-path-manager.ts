import type {
  App,
  FileStats,
  Reference,
  TFile
} from 'obsidian';

import { isReferenceCache } from '@obsidian-typings/obsidian-public-latest/implementations';
import {
  normalizePath,
  Notice
} from 'obsidian';
import { printError } from 'obsidian-dev-utils/error';
import { appendCodeBlock } from 'obsidian-dev-utils/html-element';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  join,
  makeFileName
} from 'obsidian-dev-utils/path';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

import type { CustomAttachmentLocationComponent } from './custom-attachment-location-component.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import {
  Substitutions,
  TokenValidationMode,
  validateFileName,
  validatePath
} from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';

export interface AttachmentPathManagerGetProperAttachmentPathParams {
  readonly actionContext: ActionContext;
  readonly attachmentFile: TFile;
  readonly noteFilePath: string;
  readonly reference: Reference;
}

interface AttachmentPathManagerConstructorParams {
  readonly app: App;
  readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

interface AttachmentPathManagerGetAttachmentFolderFullPathForPathParams {
  readonly actionContext: ActionContext;
  readonly attachmentFileContent?: ArrayBuffer | undefined;
  readonly attachmentFileName: string;
  readonly attachmentFileStat?: FileStats | undefined;
  readonly notePath: string;
  readonly oldNoteFilePath?: string | undefined;
}

export class AttachmentPathManager {
  private readonly app: App;
  private readonly customAttachmentLocationComponent: CustomAttachmentLocationComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;

  public constructor(params: AttachmentPathManagerConstructorParams) {
    this.app = params.app;
    this.customAttachmentLocationComponent = params.customAttachmentLocationComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  public async getAttachmentFolderFullPathForPath(params: AttachmentPathManagerGetAttachmentFolderFullPathForPathParams): Promise<string> {
    return await this.getAttachmentFolderPath(
      new Substitutions({
        actionContext: params.actionContext,
        app: this.app,
        attachmentFileContent: params.attachmentFileContent,
        attachmentFileStat: params.attachmentFileStat,
        noteFilePath: params.notePath,
        oldNoteFilePath: params.oldNoteFilePath,
        originalAttachmentFileName: params.attachmentFileName,
        pluginSettingsComponent: this.pluginSettingsComponent
      })
    );
  }

  public async getGeneratedAttachmentFileBaseName(substitutions: Substitutions): Promise<string> {
    let baseTemplate: string;
    switch (substitutions.actionContext) {
      case ActionContext.CollectAttachments:
        baseTemplate = this.pluginSettingsComponent.settings.collectedAttachmentFileName;
        break;
      case ActionContext.RenameNote:
        baseTemplate = this.pluginSettingsComponent.settings.renamedAttachmentFileName;
        break;
      default:
        baseTemplate = this.pluginSettingsComponent.settings.generatedAttachmentFileName;
        break;
    }

    baseTemplate ||= this.pluginSettingsComponent.settings.generatedAttachmentFileName;

    const path = await this.resolvePathTemplate(baseTemplate, substitutions, true);
    let validationMessage = await validatePath({
      app: this.app,
      areTokensAllowed: false,
      path,
      pluginSettingsComponent: this.pluginSettingsComponent
    });
    if (!validationMessage) {
      const parts = path.split('/');
      const fileName = ensureNonNullable(parts.at(-1));
      // eslint-disable-next-line require-atomic-updates -- Ignore possible race condition.
      validationMessage = await validateFileName({
        app: this.app,
        areSingleDotsAllowed: false,
        fileName,
        isEmptyAllowed: false,
        pluginSettingsComponent: this.pluginSettingsComponent,
        tokenValidationMode: TokenValidationMode.Error
      });
    }
    if (validationMessage) {
      new Notice(createFragment((f) => {
        f.appendText(t(($) => $.notice.generatedAttachmentFileNameIsInvalid.part1, { path, validationMessage }));
        f.appendText(' ');
        appendCodeBlock(f, t(($) => $.pluginSettingsTab.generatedAttachmentFileName.name));
        f.appendText(' ');
        f.appendText(t(($) => $.notice.generatedAttachmentFileNameIsInvalid.part2));
      }));
      const errorMessage = `Generated attachment file name "${path}" is invalid.\n${validationMessage}\nCheck your 'Generated attachment file name' setting.`;
      console.error(errorMessage, substitutions);
      throw new Error(errorMessage);
    }
    return path;
  }

  public async getProperAttachmentPath(params: AttachmentPathManagerGetProperAttachmentPathParams): Promise<null | string> {
    const attachmentFileContent = await this.app.vault.readBinary(params.attachmentFile);
    const newAttachmentName = this.pluginSettingsComponent.settings.shouldRenameCollectedAttachments
      ? makeFileName(
        await this.getGeneratedAttachmentFileBaseName(
          new Substitutions({
            actionContext: params.actionContext,
            app: this.app,
            attachmentFileContent,
            attachmentFileStat: params.attachmentFile.stat,
            cursorLine: isReferenceCache(params.reference) ? params.reference.position.start.line : 0,
            noteFilePath: params.noteFilePath,
            originalAttachmentFileName: params.attachmentFile.name,
            pluginSettingsComponent: this.pluginSettingsComponent,
            sequenceNumber: await this.customAttachmentLocationComponent.getSequenceNumber(params.noteFilePath, params.attachmentFile.path)
          })
        ),
        params.attachmentFile.extension
      )
      : params.attachmentFile.name;

    const newAttachmentFolderPath = await this.getAttachmentFolderFullPathForPath({
      actionContext: params.actionContext,
      attachmentFileContent,
      attachmentFileName: newAttachmentName,
      attachmentFileStat: params.attachmentFile.stat,
      notePath: params.noteFilePath
    });
    const newAttachmentPath = join(newAttachmentFolderPath, newAttachmentName);

    if (params.attachmentFile.path === newAttachmentPath) {
      return null;
    }

    return newAttachmentPath;
  }

  private cleanFilePathPart(part: string): string {
    let cleanPart = part.trimEnd();
    if (cleanPart === '.' || cleanPart === '..') {
      return cleanPart;
    }

    cleanPart = cleanPart.replace(/[\s.]+$/, '');
    cleanPart = this.pluginSettingsComponent.replaceSpecialCharacters(cleanPart);
    return cleanPart;
  }

  private async getAttachmentFolderPath(substitutions: Substitutions): Promise<string> {
    return await this.resolvePathTemplate(this.pluginSettingsComponent.settings.attachmentFolderPath, substitutions, false);
  }

  private async resolvePathTemplate(template: string, substitutions: Substitutions, isFileNamePart: boolean): Promise<string> {
    try {
      let resolvedPath = await substitutions.fillTemplate(template);
      const resolvedPathParts = resolvedPath.split('/').map((part) => this.cleanFilePathPart(part));
      resolvedPath = resolvedPathParts.join('/');

      const validationError = await validatePath({
        app: this.app,
        areTokensAllowed: false,
        path: resolvedPath,
        pluginSettingsComponent: this.pluginSettingsComponent
      });
      if (validationError) {
        throw new Error(`Resolved path ${resolvedPath} is invalid: ${validationError}`);
      }

      if (!isFileNamePart) {
        if (isRelativePath(resolvedPath)) {
          resolvedPath = join(substitutions.noteFolderPath, resolvedPath);
        }

        resolvedPath = normalizePath(resolvedPath);
      }

      if (resolvedPath === '.') {
        resolvedPath = '';
      }

      if (isRelativePath(resolvedPath)) {
        throw new Error('Resolved path should be absolute');
      }

      return resolvedPath;
    } catch (error) {
      new Notice(t(($) => $.notice.couldNotResolveTemplatePath, { template }));
      console.error('Could not resolve template path', {
        substitutions,
        template
      });
      printError(error);
      throw error;
    }
  }
}

function isRelativePath(path: string): boolean {
  return path === '.' || path.startsWith('./') || path === '..' || path.startsWith('../');
}
