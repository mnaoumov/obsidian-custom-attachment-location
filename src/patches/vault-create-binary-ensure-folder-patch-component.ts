import type {
  App,
  TFile,
  Vault
} from 'obsidian';

import { parentFolderPath } from '@obsidian-typings/obsidian-public-latest/implementations';
import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import { createFolderSafe } from 'obsidian-dev-utils/obsidian/vault';

interface VaultCreateBinaryEnsureFolderPatchComponentConstructorParams {
  readonly app: App;
  readonly vault: Vault;
}

export class VaultCreateBinaryEnsureFolderPatchComponent extends MonkeyAroundComponent {
  private readonly app: App;
  private readonly vault: Vault;

  public constructor(params: VaultCreateBinaryEnsureFolderPatchComponentConstructorParams) {
    super();
    this.app = params.app;
    this.vault = params.vault;
  }

  public override onload(): void {
    this.registerMethodPatch({
      $object: this.vault,
      methodName: 'createBinary',
      patchHandler: ({
        fallback,
        originalArguments: [path]
      }) => {
        /*
         * The plugin no longer lets a dry `getAvailablePathForAttachments` resolution eagerly create
         * an attachment folder (issue #26). Core-native save flows that go through the base method
         * (audio recorder, downloaded-image paste, dropped-file import) resolve the path and then
         * `createBinary` straight into it, so the folder must be materialized at the moment an
         * attachment is actually written. `vault.createBinary` does not create missing parents, so do
         * it here — folders now appear exactly when an attachment is saved, never on a bare probe.
         */
        return (async (): Promise<TFile> => {
          const folderPath = parentFolderPath(path);
          if (folderPath !== '/' && !await this.vault.exists(folderPath)) {
            await createFolderSafe(this.app, folderPath);
          }
          return await fallback();
        })();
      }
    });
  }
}
