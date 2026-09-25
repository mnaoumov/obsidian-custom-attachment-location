import type { Vault } from 'obsidian';
import type { GetAvailablePathForAttachmentsFunctionExtended } from 'obsidian-dev-utils/obsidian/attachment-path';

import { AttachmentPathContext } from 'obsidian-dev-utils/obsidian/attachment-path';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import { makeFileName } from 'obsidian-dev-utils/path';

import type { AttachmentPathManager } from '../attachment-path-manager.ts';
import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import {
  SelfWriteClaim,
  selfWriteRegistry
} from '../self-write-registry.ts';

interface VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams {
  readonly attachmentPathManager: AttachmentPathManager;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly vault: Vault;
}

export class VaultGetAvailablePathForAttachmentsPatchComponent extends MonkeyAroundComponent {
  private readonly attachmentPathManager: AttachmentPathManager;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly vault: Vault;

  public constructor(params: VaultGetAvailablePathForAttachmentsPatchComponentConstructorParams) {
    super();
    this.vault = params.vault;
    this.attachmentPathManager = params.attachmentPathManager;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
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
          shouldSkipGeneratedAttachmentFileName: true,
          shouldSkipMissingAttachmentFolderCreation: true
        });

        /*
         * The caller named the file and the resolver kept that name, so the claim the manager just made is weaker
         * than one on a name this plugin chose. It still covers core Obsidian's audio recorder and file imports,
         * but not a PLUGIN that asks for a folder and writes its own name into it — Excalidraw's
         * `Pasted Image <date>.png` (issue #65), which is another plugin's attachment like any other.
         */
        selfWriteRegistry.register(attachmentPath, SelfWriteClaim.OutsideCaller);
        return attachmentPath;
      },
      postPatchHandler: ({
        patchedMethod
      }) => {
        /*
         * The attachment-unit-folder designation rides alongside `extended` because it answers the same
         * kind of question — what this plugin's attachment policy says — for a reader that must not have
         * to know which plugin is answering. The delete interception needs it to keep a designated
         * folder whole (issue #70), and it moved to another plugin in 12.0.0.
         *
         * `obsidian-dev-utils` declares both members, so annotating the assembled method with its
         * interface is what keeps this publisher and every reader — this plugin's own collecting and
         * deleting commands included — agreeing on one shape instead of on two copies of it.
         */
        const extendedMethod: GetAvailablePathForAttachmentsFunctionExtended = Object.assign(patchedMethod, {
          checkIsAttachmentUnitFolder: (folderPath: string) => this.pluginSettingsComponent.settings.isAttachmentUnitFolder(folderPath),
          extended: this.attachmentPathManager.getAvailablePathForAttachments.bind(this.attachmentPathManager)
        });

        return extendedMethod;
      }
    });
  }
}
