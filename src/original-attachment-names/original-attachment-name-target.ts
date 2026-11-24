/**
 * @file
 *
 * Decides which attachment the `Show original file name` menu item and the `Copy original file name` command act on,
 * and what name the store holds for it, so the two can never disagree.
 */

import type {
  App,
  TAbstractFile
} from 'obsidian';

import {
  getLinkAtEditorPosition,
  getLinkAtPositionTarget
} from '@mnaoumov/obsidian-lib/link-at-position';
import { TFile } from 'obsidian';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

/**
 * Params for {@link getActiveOriginalAttachmentNameTarget}.
 */
export interface GetActiveOriginalAttachmentNameTargetParams extends OriginalAttachmentNameTargetContext {
  readonly app: App;
}

/**
 * Params for {@link getOriginalAttachmentNameTarget}.
 */
export interface GetOriginalAttachmentNameTargetParams extends OriginalAttachmentNameTargetContext {
  readonly file: null | TAbstractFile;
}

/**
 * An attachment and the name the store holds for it.
 */
export interface OriginalAttachmentNameTarget {
  /**
   * The attachment.
   */
  readonly attachment: TFile;

  /**
   * The name the attachment arrived with, or `null` when the store holds none (or an empty one).
   */
  readonly originalFileName: null | string;
}

/**
 * The part of the plugin {@link getOriginalAttachmentNameTarget} and {@link getActiveOriginalAttachmentNameTarget} read.
 */
export interface OriginalAttachmentNameTargetContext {
  readonly originalAttachmentNamesComponent: Pick<OriginalAttachmentNamesComponent, 'get'>;
  readonly pluginSettingsComponent: Pick<PluginSettingsComponent, 'isNoteEx'>;
}

/**
 * Finds the attachment the active view is about: the active file when it is an attachment, otherwise the attachment a
 * link under the active editor's cursor resolves to.
 *
 * The two never compete: a cursor exists only in a note's editor, and a note is never an attachment.
 *
 * @param params - The app and the plugin parts read.
 * @returns The attachment and its stored name, or `null` when the active view is about no attachment.
 */
export function getActiveOriginalAttachmentNameTarget(params: GetActiveOriginalAttachmentNameTargetParams): null | OriginalAttachmentNameTarget {
  const activeFileTarget = getOriginalAttachmentNameTarget({ ...params, file: params.app.workspace.getActiveFile() });
  if (activeFileTarget) {
    return activeFileTarget;
  }

  const activeEditor = params.app.workspace.activeEditor;
  const editor = activeEditor?.editor;
  const sourceFile = activeEditor?.file;
  if (!editor || !sourceFile) {
    return null;
  }

  const link = getLinkAtEditorPosition({ editor });
  if (!link) {
    return null;
  }

  const linkTarget = getLinkAtPositionTarget({ app: params.app, link, sourcePath: sourceFile.path });
  return getOriginalAttachmentNameTarget({ ...params, file: linkTarget });
}

/**
 * Reads the stored name of a file that is an attachment: a file that is not a note (`.md`, `.canvas`, `.base`, unless
 * the hand-over settings treat it as an attachment).
 *
 * @param params - The file and the plugin parts read.
 * @returns The attachment and its stored name, or `null` for a folder, a note or no file.
 */
export function getOriginalAttachmentNameTarget(params: GetOriginalAttachmentNameTargetParams): null | OriginalAttachmentNameTarget {
  const file = params.file;
  if (!(file instanceof TFile) || params.pluginSettingsComponent.isNoteEx(file)) {
    return null;
  }
  const storedName = params.originalAttachmentNamesComponent.get(file.path);
  return {
    attachment: file,
    // An empty stored name counts as none: there is nothing to show or copy.
    originalFileName: storedName === '' ? null : storedName
  };
}
