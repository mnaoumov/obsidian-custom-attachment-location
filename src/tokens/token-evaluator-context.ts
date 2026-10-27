import type {
  App,
  FileStats
} from 'obsidian';

import { AttachmentPathContext } from '@mnaoumov/obsidian-lib/attachment-path';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { TokenValidator } from './token-validator.ts';

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
   * An attachment another plugin created directly in the vault, caught after the fact.
   */
  ExternalAttachmentCreated = 'ExternalAttachmentCreated',

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
   * A read through this plugin's published API. Answers a question without performing an action, so it must
   * never ask the user anything: an audit walking a vault would otherwise raise one dialog per note.
   */
  ReadApi = 'ReadApi',

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
 * Which template a token is being evaluated in.
 *
 * Tells a token what the value it returns will become, which is what lets `{{prompt}}` ask a question
 * that matches what the user is actually deciding — a file name, a folder, or neither.
 */
export enum TemplatePart {
  /**
   * The generated attachment file name template.
   */
  FileName = 'FileName',

  /**
   * The attachment folder path template.
   */
  Folder = 'Folder',

  /**
   * Any other template, e.g. the Markdown URL format. Neither a file name nor a folder.
   */
  Other = 'Other'
}

/**
 * Context passed to token evaluators.
 */
export interface TokenEvaluatorContext {
  /**
   * An abort signal to control the execution of the function.
   */
  readonly abortSignal: AbortSignal;

  /**
   * An action context.
   */
  readonly actionContext: ActionContext;

  /**
   * An Obsidian app instance.
   */
  readonly app: App;

  /**
   * An extension of the attachment file as it is right now, without its dot. For a paste or a drop, the incoming
   * file's.
   */
  readonly attachmentFileExtension: string;

  /**
   * A name of the attachment file as it is right now, without its extension. For a paste or a drop, the incoming
   * file's.
   */
  readonly attachmentFileName: string;

  /**
   * Stats of the attachment file.
   *
   * `undefined` if the attachment file stats is not known.
   *
   * @remark It may be initialized only partially. Uninitialized {@link FileStats.ctime} and {@link FileStats.mtime} will be `0`.
   */
  readonly attachmentFileStats: FileStats | undefined;

  /**
   * A cursor line.
   *
   * `null` if the cursor line is not known.
   */
  readonly cursorLine: null | number;

  /**
   * Fills a template with the current context.
   */
  readonly fillTemplate: (template: string) => Promise<string>;

  /**
   * The format of the token: `null` for none, the text itself for the scalar shorthand (`{{date:YYYY-MM-DD}}`),
   * and the parsed JSON5 object otherwise.
   */
  readonly format: null | Record<string, unknown> | string;

  /**
   * A full template string.
   */
  readonly fullTemplate: string;

  /**
   * A generated attachment file name.
   *
   * Empty string if the attachment file name is not fully generated yet.
   */
  readonly generatedAttachmentFileName: string;

  /**
   * A generated attachment file path.
   *
   * Empty string if the attachment file path is not fully generated yet.
   */
  readonly generatedAttachmentFilePath: string;

  /**
   * Lazily reads the content of the attachment file, memoizing the result.
   *
   * The bytes are read on demand only the first time this is called; subsequent calls return the
   * cached value without re-reading. For the default templates nothing pulls the bytes, so the
   * potentially expensive (size-proportional) `readBinary` never runs.
   *
   * @returns A {@link Promise} that resolves to the content of the attachment file, or `undefined`
   * when there is no attachment file to read.
   */
  readonly getAttachmentFileContent: () => Promise<ArrayBuffer | undefined>;

  /**
   * A name of the note file.
   */
  readonly noteFileName: string;

  /**
   * A path of the note file.
   */
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
  noteFilePath: string;

  /**
   * A name of the note folder.
   */
  readonly noteFolderName: string;

  /**
   * A path of the note folder.
   */
  readonly noteFolderPath: string;

  /**
   * An Obsidian API.
   *
   * {@link https://github.com/obsidianmd/obsidian-api/blob/master/obsidian.d.ts}
   */
  readonly obsidian: typeof import('obsidian');

  /**
   * A name of the old note file.
   */
  readonly oldNoteFileName: string;

  /**
   * A path of the old note file.
   */
  readonly oldNoteFilePath: string;

  /**
   * A name of the old note folder.
   */
  readonly oldNoteFolderName: string;

  /**
   * A path of the old note folder.
   */
  readonly oldNoteFolderPath: string;

  /**
   * An extension of the name the attachment arrived with, without its dot. Pairs with
   * {@link originalAttachmentFileName}.
   */
  readonly originalAttachmentFileExtension: string;

  /**
   * A name the attachment arrived with, without its extension: the name it had when it was pasted, dropped, shared or
   * downloaded, kept across every rename this plugin sees.
   *
   * When it is not known — the file predates the record, or was renamed outside Obsidian — this is
   * {@link attachmentFileName}, and the plugin warns that it used the current name.
   */
  readonly originalAttachmentFileName: string;

  /**
   * Plugin settings component.
   */
  readonly pluginSettingsComponent: PluginSettingsComponent;

  /**
   * A sequence number of the attachment file.
   *
   * `0` if the sequence number is not known.
   */
  readonly sequenceNumber: number;

  /**
   * Which template the token is being evaluated in — the generated file name, the attachment folder
   * path, or neither.
   */
  readonly templatePart: TemplatePart;

  /**
   * A token being evaluated.
   */
  readonly token: string;

  /**
   * An end offset of the token within the full template.
   */
  readonly tokenEndOffset: number;

  /**
   * A start offset of the token within the full template.
   */
  readonly tokenStartOffset: number;

  /**
   * Validator.
   */
  readonly tokenValidator: TokenValidator;

  /**
   * A token with the format.
   */
  readonly tokenWithFormat: string;
}

/**
 * Converts an {@link ActionContext} to an {@link AttachmentPathContext}.
 *
 * `AttachmentPathContext` is a subset of `ActionContext` by string value.
 * Contexts that have no equivalent map to `AttachmentPathContext.Unknown`.
 */
export function actionContextToAttachmentPathContext(context: ActionContext): AttachmentPathContext {
  switch (context) {
    case ActionContext.DeleteNote: {
      return AttachmentPathContext.DeleteNote;
    }
    case ActionContext.RenameNote: {
      return AttachmentPathContext.RenameNote;
    }
    default: {
      return AttachmentPathContext.Unknown;
    }
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
    case AttachmentPathContext.DeleteNote: {
      return ActionContext.DeleteNote;
    }
    case AttachmentPathContext.RenameNote: {
      return ActionContext.RenameNote;
    }
    default: {
      return ActionContext.Unknown;
    }
  }
}

/**
 * Whether the action being performed has no user to ask.
 *
 * Tokens that would otherwise open a dialog consult this instead of naming the contexts themselves, so a
 * context added later is handled in one place rather than in every interactive token.
 *
 * @param context - The action context.
 * @returns `true` when nothing may be asked.
 */
export function isNonInteractiveActionContext(context: ActionContext): boolean {
  return context === ActionContext.ReadApi || context === ActionContext.ValidateTokens;
}
