import type {
  App,
  FileStats
} from 'obsidian';

import { AttachmentPathContext } from 'obsidian-dev-utils/obsidian/attachment-path';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { ValidatePathParams } from './substitutions.ts';

/**
 * An action context.
 */
export enum ActionContext {
  /**
   * Collect attachments.
   */
  CollectAttachments = 'CollectAttachments',

  /**
   * Delete note.
   */
  DeleteNote = 'DeleteNote',

  /**
   * Import files.
   */
  ImportFiles = 'ImportFiles',

  /**
   * Move attachment to proper folder.
   */
  MoveAttachmentToProperFolder = 'MoveAttachmentToProperFolder',

  /**
   * Open file.
   */
  OpenFile = 'OpenFile',

  /**
   * Rename note.
   */
  RenameNote = 'RenameNote',

  /**
   * Save attachment.
   */
  SaveAttachment = 'SaveAttachment',

  /**
   * Unknown.
   */
  Unknown = 'Unknown',

  /**
   * Validate tokens.
   */
  ValidateTokens = 'ValidateTokens'
}

/**
 * Context passed to token evaluators.
 */
export interface TokenEvaluatorContext {
  /**
   * An abort signal to control the execution of the function.
   */
  abortSignal: AbortSignal;

  /**
   * An action context.
   */
  actionContext: ActionContext;

  /**
   * An Obsidian app instance.
   */
  app: App;

  /**
   * A content of the attachment file.
   *
   * `undefined` if the attachment file content is not known.
   */
  attachmentFileContent: ArrayBuffer | undefined;

  /**
   * Stats of the attachment file.
   *
   * `undefined` if the attachment file stats is not known.
   *
   * @remark It may be initialized only partially. Uninitialized {@link FileStats.ctime} and {@link FileStats.mtime} will be `0`.
   */
  attachmentFileStat: FileStats | undefined;

  /**
   * A cursor line.
   *
   * `null` if the cursor line is not known.
   */
  cursorLine: null | number;

  /**
   * Fills a template with the current context.
   */
  fillTemplate(template: string): Promise<string>;

  /**
   * The format of the token.
   */
  format: null | Record<string, unknown>;

  /**
   * A full template string.
   */
  fullTemplate: string;

  /**
   * A generated attachment file name.
   *
   * Empty string if the attachment file name is not fully generated yet.
   */
  generatedAttachmentFileName: string;

  /**
   * A generated attachment file path.
   *
   * Empty string if the attachment file path is not fully generated yet.
   */
  generatedAttachmentFilePath: string;

  /**
   * A name of the note file.
   */
  noteFileName: string;

  /**
   * A path of the note file.
   */
  noteFilePath: string;

  /**
   * A name of the note folder.
   */
  noteFolderName: string;

  /**
   * A path of the note folder.
   */
  noteFolderPath: string;

  /**
   * An Obsidian API.
   *
   * {@link https://github.com/obsidianmd/obsidian-api/blob/master/obsidian.d.ts}
   */
  obsidian: typeof import('obsidian');

  /**
   * A name of the old note file.
   */
  oldNoteFileName: string;

  /**
   * A path of the old note file.
   */
  oldNoteFilePath: string;

  /**
   * A name of the old note folder.
   */
  oldNoteFolderName: string;

  /**
   * A path of the old note folder.
   */
  oldNoteFolderPath: string;

  /**
   * An extension of the original attachment file.
   */
  originalAttachmentFileExtension: string;

  /**
   * A name of the original attachment file.
   */
  originalAttachmentFileName: string;

  /**
   * Plugin settings component.
   */
  pluginSettingsComponent: PluginSettingsComponent;

  /**
   * A sequence number of the attachment file.
   *
   * `0` if the sequence number is not known.
   */
  sequenceNumber: number;

  /**
   * A token being evaluated.
   */
  token: string;

  /**
   * An end offset of the token within the full template.
   */
  tokenEndOffset: number;

  /**
   * A start offset of the token within the full template.
   */
  tokenStartOffset: number;

  /**
   * A token with the format.
   */
  tokenWithFormat: string;

  /**
   * Validates a path.
   */
  validatePath(options: ValidatePathParams): Promise<string>;
}

/**
 * Converts an {@link ActionContext} to an {@link AttachmentPathContext}.
 *
 * `AttachmentPathContext` is a subset of `ActionContext` by string value.
 * Contexts that have no equivalent map to `AttachmentPathContext.Unknown`.
 */
export function actionContextToAttachmentPathContext(context: ActionContext): AttachmentPathContext {
  switch (context) {
    case ActionContext.DeleteNote:
      return AttachmentPathContext.DeleteNote;
    case ActionContext.RenameNote:
      return AttachmentPathContext.RenameNote;
    default:
      return AttachmentPathContext.Unknown;
  }
}

/**
 * Converts an {@link AttachmentPathContext} to an {@link ActionContext}.
 *
 * `AttachmentPathContext` is a subset of `ActionContext` by string value.
 * Contexts that have no equivalent map to `ActionContext.Unknown`.
 */
export function attachmentPathContextToActionContext(context: AttachmentPathContext): ActionContext {
  switch (context) {
    case AttachmentPathContext.DeleteNote:
      return ActionContext.DeleteNote;
    case AttachmentPathContext.RenameNote:
      return ActionContext.RenameNote;
    default:
      return ActionContext.Unknown;
  }
}
