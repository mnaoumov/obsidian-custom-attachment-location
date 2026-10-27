import type { Vault } from 'obsidian';

import { AttachmentPathContext } from '@mnaoumov/obsidian-lib/attachment-path';
import { MonkeyAroundComponent } from '@mnaoumov/obsidian-lib/components/monkey-around-component';
import { makeFileName } from '@mnaoumov/typescript-lib/path';

import type { AttachmentPathManager } from './attachment-path-manager.ts';

import {
  SelfWriteClaim,
  selfWriteRegistry
} from '../externally-created-attachments/self-write-registry.ts';

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
      $object: this.vault,
      methodName: 'getAvailablePathForAttachments',
      patchHandler: async ({
        originalArguments: [attachmentFileBaseName, attachmentFileExtension, notePathOrFile]
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
        const attachmentPath = await this.attachmentPathManager.getAvailablePathForAttachments({
          attachmentFileBaseName,
          attachmentFileExtension,
          context: AttachmentPathContext.Unknown,
          notePathOrFile: notePathOrFile ?? null,
          oldAttachmentPathOrFile: makeFileName({
            fileBaseName: attachmentFileBaseName,
            fileExtension: attachmentFileExtension
          }),
          readAttachmentFileContent: null,
          shouldReplaceSpecialCharactersInKeptFileName: true,
          shouldSkipGeneratedAttachmentFileName: true,
          shouldSkipMissingAttachmentFolderCreation: true
        });

        /*
         * The caller named the file and the resolver kept that name, so the claim the manager just made is weaker
         * than one on a name this plugin chose. It still covers core Obsidian's audio recorder and file imports,
         * but not a PLUGIN that asks for a folder and writes its own name into it — `Excalidraw`'s
         * `Pasted Image <date>.png` (issue #65), which is another plugin's attachment like any other.
         */
        selfWriteRegistry.register(attachmentPath, SelfWriteClaim.OutsideCaller);
        return attachmentPath;
      }
    });
  }
}
