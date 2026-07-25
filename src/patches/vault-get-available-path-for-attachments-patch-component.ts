import type { Vault } from 'obsidian';

import { AttachmentPathContext } from 'obsidian-dev-utils/obsidian/attachment-path';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import { makeFileName } from 'obsidian-dev-utils/path';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';

interface VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams {
  readonly attachmentPathManager: AttachmentPathManager;
  readonly vault: Vault;
}

export class VaultGetAvailablePathForAttachmentsPatchComponent extends MonkeyAroundComponent {
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly vault: Vault;

  public constructor(params: VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams) {
    super();
    this.vault = params.vault;
    this.attachmentPathManager = params.attachmentPathManager;
  }

  public override onload(): void {
    this.registerMethodPatch({
      methodName: 'getAvailablePathForAttachments',
      obj: this.vault,
      patchHandler: ({
        originalArgs: [attachmentFileBaseName, attachmentFileExtension, notePathOrFile]
      }) => {
        /*
         * The base method is invoked for dry resolutions (Obsidian core and third-party plugins probe
         * where an attachment would land without actually saving one). Core's own implementation
         * unconditionally `createFolder`s the resolved attachment folder, and because the plugin
         * resolves that folder from the note-file-name template, a probe would eagerly materialize an
         * empty per-note folder (issue #26). Delegate to the plugin's resolver with
         * `shouldSkipMissingAttachmentFolderCreation: true` so no folder is created for a resolution.
         * Real saves create their folder through the actual write path, not here.
         */
        return this.attachmentPathManager.getAvailablePathForAttachments({
          attachmentFileBaseName,
          attachmentFileExtension,
          context: AttachmentPathContext.Unknown,
          notePathOrFile: notePathOrFile ?? null,
          oldAttachmentPathOrFile: makeFileName({
            fileBaseName: attachmentFileBaseName,
            fileExtension: attachmentFileExtension
          }),
          readAttachmentFileContent: null,
          shouldSkipGeneratedAttachmentFileName: true,
          shouldSkipMissingAttachmentFolderCreation: true
        });
      },
      postPatchHandler: ({
        patchedMethod
      }) => {
        return Object.assign(patchedMethod, {
          extended: this.attachmentPathManager.getAvailablePathForAttachments.bind(this.attachmentPathManager)
        });
      }
    });
  }
}
