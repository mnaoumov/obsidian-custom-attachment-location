import type {
  App,
  FileStats
} from 'obsidian';

import {
  normalizePath,
  Notice
} from 'obsidian';
import { printError } from 'obsidian-dev-utils/error';
import { appendCodeBlock } from 'obsidian-dev-utils/html-element';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { join } from 'obsidian-dev-utils/path';
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

export async function getAttachmentFolderFullPathForPath(
  customAttachmentLocationComponent: CustomAttachmentLocationComponent,
  actionContext: ActionContext,
  notePath: string,
  attachmentFileName: string,
  pluginSettingsComponent: PluginSettingsComponent,
  oldNoteFilePath?: string,
  attachmentFileContent?: ArrayBuffer,
  attachmentFileStat?: FileStats
): Promise<string> {
  return await getAttachmentFolderPath(
    customAttachmentLocationComponent.app,
    new Substitutions({
      actionContext,
      app: customAttachmentLocationComponent.app,
      attachmentFileContent,
      attachmentFileStat,
      noteFilePath: notePath,
      oldNoteFilePath,
      originalAttachmentFileName: attachmentFileName,
      pluginSettingsComponent
    }),
    pluginSettingsComponent
  );
}

export async function getGeneratedAttachmentFileBaseName(
  app: App,
  substitutions: Substitutions,
  pluginSettingsComponent: PluginSettingsComponent
): Promise<string> {
  let baseTemplate: string;
  switch (substitutions.actionContext) {
    case ActionContext.CollectAttachments:
      baseTemplate = pluginSettingsComponent.settings.collectedAttachmentFileName;
      break;
    case ActionContext.RenameNote:
      baseTemplate = pluginSettingsComponent.settings.renamedAttachmentFileName;
      break;
    default:
      baseTemplate = pluginSettingsComponent.settings.generatedAttachmentFileName;
      break;
  }

  baseTemplate ||= pluginSettingsComponent.settings.generatedAttachmentFileName;

  const path = await resolvePathTemplate(app, pluginSettingsComponent, baseTemplate, substitutions, true);
  let validationMessage = await validatePath({
    app,
    areTokensAllowed: false,
    path,
    pluginSettingsComponent
  });
  if (!validationMessage) {
    const parts = path.split('/');
    const fileName = ensureNonNullable(parts.at(-1));
    // eslint-disable-next-line require-atomic-updates -- Ignore possible race condition.
    validationMessage = await validateFileName({
      app,
      areSingleDotsAllowed: false,
      fileName,
      isEmptyAllowed: false,
      pluginSettingsComponent,
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

function cleanFilePathPart(pluginSettingsComponent: PluginSettingsComponent, part: string): string {
  let cleanPart = part.trimEnd();
  if (cleanPart === '.' || cleanPart === '..') {
    return cleanPart;
  }

  cleanPart = cleanPart.replace(/[\s.]+$/, '');
  cleanPart = pluginSettingsComponent.replaceSpecialCharacters(cleanPart);
  return cleanPart;
}

async function getAttachmentFolderPath(app: App, substitutions: Substitutions, pluginSettingsComponent: PluginSettingsComponent): Promise<string> {
  return await resolvePathTemplate(app, pluginSettingsComponent, pluginSettingsComponent.settings.attachmentFolderPath, substitutions, false);
}

function isRelativePath(path: string): boolean {
  return path === '.' || path.startsWith('./') || path === '..' || path.startsWith('../');
}

async function resolvePathTemplate(app: App, pluginSettingsComponent: PluginSettingsComponent, template: string, substitutions: Substitutions, isFileNamePart: boolean): Promise<string> {
  try {
    let resolvedPath = await substitutions.fillTemplate(template);
    const resolvedPathParts = resolvedPath.split('/').map((part) => cleanFilePathPart(pluginSettingsComponent, part));
    resolvedPath = resolvedPathParts.join('/');

    const validationError = await validatePath({
      app,
      areTokensAllowed: false,
      path: resolvedPath,
      pluginSettingsComponent
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
