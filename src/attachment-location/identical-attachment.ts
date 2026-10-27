import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { FileChange } from '@mnaoumov/obsidian-lib/file-change';
import type { PathOrFile } from '@mnaoumov/obsidian-lib/file-system';
import type { ResourceLockComponent } from '@mnaoumov/obsidian-lib/resource-lock';
import type {
  App,
  TFile
} from 'obsidian';

import { getCanvasReferences } from '@mnaoumov/obsidian-lib/canvas';
import { applyFileChanges } from '@mnaoumov/obsidian-lib/file-change';
import {
  getAbstractFileOrNull,
  getFileOrNull,
  isCanvasFile,
  isFile
} from '@mnaoumov/obsidian-lib/file-system';
import {
  editLinks,
  extractLinkFile,
  updateLink
} from '@mnaoumov/obsidian-lib/link';
import { getBacklinksForFileSafe } from '@mnaoumov/obsidian-lib/metadata-cache';
import {
  isCanvasTextNodeReference,
  referenceToFileChange
} from '@mnaoumov/obsidian-lib/reference';
import { trashSafe } from '@mnaoumov/obsidian-lib/vault';
import { printError } from '@mnaoumov/typescript-lib/error';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';

interface FindIdenticalAttachmentFileParams {
  readonly app: App;
  readonly attachmentPathOrFile: PathOrFile;
  readonly destinationPath: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

interface MergeIntoIdenticalAttachmentParams {
  readonly app: App;
  readonly attachmentFile: TFile;
  readonly identicalFile: TFile;
  readonly pluginNoticeComponent: null | PluginNoticeComponent;
  readonly resourceLockComponent: null | ResourceLockComponent;

  /**
   * Canvases whose references the caller rewrites itself.
   *
   * `Collect attachments` rewrites the canvas it is collecting from its own snapshot of that canvas's
   * references, after its loop. Rewriting the same canvas here as well would leave that snapshot stale.
   */
  readonly skippedCanvasPaths?: ReadonlySet<string>;
}

interface RepointCanvasReferencesParams extends MergeIntoIdenticalAttachmentParams {
  readonly canvasFile: TFile;
}

/**
 * Finds the file a move onto `destinationPath` would collide with, when that file holds exactly the same
 * bytes as the attachment being moved (discussion #96).
 *
 * The match is by CONTENT. A name match would merge attachments that only share a name, which several
 * default setups produce: an empty collected-name template keeps `image.png` for every note's image, and
 * a template with no unique part names all of a note's attachments alike.
 *
 * @param params - The parameters.
 * @returns The identical file, or `null` when the setting is off, the destination is free, holds a
 * folder or the attachment itself, holds different bytes, or could not be read.
 */
export async function findIdenticalAttachmentFile(params: FindIdenticalAttachmentFileParams): Promise<null | TFile> {
  if (!params.pluginSettingsComponent.settings.shouldDeduplicateIdenticalAttachments) {
    return null;
  }

  const attachmentFile = getFileOrNull({
    app: params.app,
    pathOrFile: params.attachmentPathOrFile
  });
  // Case-insensitive, as the duplicate-name suffix is: `Image.png` occupies `image.png` on most file systems.
  const occupant = getAbstractFileOrNull({
    app: params.app,
    isCaseInsensitive: true,
    pathOrFile: params.destinationPath
  });

  if (!attachmentFile || !isFile(occupant) || occupant === attachmentFile || occupant.stat.size !== attachmentFile.stat.size) {
    return null;
  }

  try {
    const [attachmentContent, occupantContent] = await Promise.all([
      params.app.vault.readBinary(attachmentFile),
      params.app.vault.readBinary(occupant)
    ]);
    return areBytesEqual(attachmentContent, occupantContent) ? occupant : null;
  } catch (error) {
    // A read that fails proves nothing about the two files, and the suffix loses nothing. Never trash on a guess.
    console.warn(`Could not compare attachment ${attachmentFile.path} with ${occupant.path}; keeping both.`);
    printError(error);
    return null;
  }
}

/**
 * Points every reference to `attachmentFile` at `identicalFile`, then moves `attachmentFile` to the trash.
 *
 * Body and frontmatter links are found through the backlinks. Canvases are scanned one by one, because
 * Obsidian does not index them into the metadata cache. The trash goes through `fileManager.trashFile`, so
 * the user's own choice of trash applies, and a genuine mismatch stays recoverable. An indexed reference the
 * rewrite could not change keeps the attachment where it is, since trashing it would break that reference.
 *
 * @param params - The parameters.
 */
export async function mergeIntoIdenticalAttachment(params: MergeIntoIdenticalAttachmentParams): Promise<void> {
  const { app, attachmentFile, identicalFile } = params;

  const backlinks = await getBacklinksForFileSafe({
    app,
    pathOrFile: attachmentFile
  });

  for (const notePath of backlinks.keys()) {
    const noteFile = app.vault.getFileByPath(notePath);
    if (!noteFile || isCanvasFile(noteFile)) {
      continue;
    }

    await editLinks({
      app,
      linkConverter: (link) =>
        extractLinkFile({ app, link, sourcePathOrFile: noteFile }) === attachmentFile
          ? updateLink({
            app,
            link,
            newSourcePathOrFile: noteFile,
            newTargetPathOrFile: identicalFile,
            oldTargetPathOrFile: attachmentFile
          })
          : undefined,
      pathOrFile: noteFile,
      pluginNoticeComponent: params.pluginNoticeComponent,
      resourceLockComponent: params.resourceLockComponent
    });
  }

  for (const canvasFile of app.vault.getFiles()) {
    if (!isCanvasFile(canvasFile) || params.skippedCanvasPaths?.has(canvasFile.path)) {
      continue;
    }

    await repointCanvasReferences({ ...params, canvasFile });
  }

  const remainingBacklinks = await getBacklinksForFileSafe({
    app,
    pathOrFile: attachmentFile
  });
  /*
   * A canvas never counts. Every one was either rewritten above or is the caller's to rewrite, and Obsidian
   * re-indexes a canvas lazily, so its backlink outlives the rewrite that removed it.
   */
  const remainingNotePaths = remainingBacklinks.keys().filter((notePath) => !isCanvasFile(notePath));
  if (remainingNotePaths.length > 0) {
    console.warn(
      `Keeping attachment ${attachmentFile.path}, identical to ${identicalFile.path}, as it is still referenced by:\n${remainingNotePaths.map((notePath) => `- ${notePath}`).join('\n')}`
    );
    return;
  }

  await trashSafe(app, attachmentFile);
}

function areBytesEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  const aBytes = new Uint8Array(a);
  const bBytes = new Uint8Array(b);
  return aBytes.every((byte, index) => byte === bBytes[index]);
}

async function repointCanvasReferences(params: RepointCanvasReferencesParams): Promise<void> {
  const { app, attachmentFile, canvasFile, identicalFile } = params;
  const changes: FileChange[] = [];

  for (const reference of await getCanvasReferences(app, canvasFile)) {
    const linkFile = extractLinkFile({
      app,
      link: reference,
      sourcePathOrFile: canvasFile
    });
    if (linkFile !== attachmentFile) {
      continue;
    }

    changes.push(referenceToFileChange(
      reference,
      isCanvasTextNodeReference(reference)
        ? updateLink({
          app,
          link: reference.originalReference,
          newSourcePathOrFile: canvasFile,
          newTargetPathOrFile: identicalFile,
          oldSourcePathOrFile: canvasFile,
          oldTargetPathOrFile: attachmentFile
        })
        : identicalFile.path
    ));
  }

  if (changes.length === 0) {
    return;
  }

  await applyFileChanges({
    app,
    changesProvider: changes,
    pathOrFile: canvasFile,
    pluginNoticeComponent: params.pluginNoticeComponent,
    resourceLockComponent: params.resourceLockComponent
  });
}
