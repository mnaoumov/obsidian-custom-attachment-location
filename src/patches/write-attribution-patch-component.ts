import type {
  DataAdapter,
  Vault
} from 'obsidian';

import { MonkeyAroundComponent } from 'obsidian-dev-utils/obsidian/components/monkey-around-component';
import { extname } from 'obsidian-dev-utils/path';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import {
  captureStackTrace,
  findCreatingPluginId
} from '../creating-plugin-attribution.ts';
import { foreignWriteRegistry } from '../foreign-write-registry.ts';

/**
 * The extension of a note, which is never the attachment this attribution is for.
 *
 * Checked first because `adapter.write` runs on every note save, and skipping those keeps the stack
 * capture off the one genuinely hot path among the patched methods.
 */
const NOTE_FILE_EXTENSION = '.md';

interface WriteAttributionPatchComponentConstructorParams {
  readonly pluginId: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly vault: Vault;
}

/**
 * Records which plugin wrote which path, so an attachment another plugin creates can be judged against the
 * include / exclude plugin list (issue #77).
 *
 * The stack is captured at the WRITE, not in `vault.on('create')`: the event is dispatched from the
 * adapter's reconciliation, several awaits after the calling plugin's frame has left the stack. See
 * `creating-plugin-attribution.ts` for why a `plugin:<id>` frame identifies the caller at all.
 *
 * Four entry points, because a plugin writing an attachment reaches the disk through any of them:
 * `Vault.create` / `Vault.createBinary` for a well-behaved plugin, and the two `DataAdapter` methods for
 * one that bypasses the vault (which also catches the vault's own delegation, harmlessly re-recording the
 * same path and plugin).
 *
 * Costs nothing at all unless a list mode is selected — under `None` and `All` the plugin id is never
 * consulted, so no stack is ever captured.
 */
export class WriteAttributionPatchComponent extends MonkeyAroundComponent {
  private readonly adapter: DataAdapter;
  private readonly pluginId: string;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly vault: Vault;

  public constructor(params: WriteAttributionPatchComponentConstructorParams) {
    super();
    this.pluginId = params.pluginId;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.vault = params.vault;
    this.adapter = params.vault.adapter;
  }

  public override onload(): void {
    this.registerMethodPatch({
      $object: this.vault,
      methodName: 'create',
      patchHandler: ({ fallback, originalArguments: [path] }) => {
        this.attributeWrite(path);
        return fallback();
      }
    });

    this.registerMethodPatch({
      $object: this.vault,
      methodName: 'createBinary',
      patchHandler: ({ fallback, originalArguments: [path] }) => {
        this.attributeWrite(path);
        return fallback();
      }
    });

    this.registerMethodPatch({
      $object: this.adapter,
      methodName: 'write',
      patchHandler: ({ fallback, originalArguments: [normalizedPath] }) => {
        this.attributeWrite(normalizedPath);
        return fallback();
      }
    });

    this.registerMethodPatch({
      $object: this.adapter,
      methodName: 'writeBinary',
      patchHandler: ({ fallback, originalArguments: [normalizedPath] }) => {
        this.attributeWrite(normalizedPath);
        return fallback();
      }
    });
  }

  /**
   * Records the plugin on the current call stack as the writer of `path`.
   *
   * Silent when there is nothing to attribute — no list mode selected, a note being saved, or no foreign
   * plugin on the stack (core Obsidian, a sync client, or this plugin's own write, which the self-write
   * registry already claims).
   *
   * @param path - The vault path being written.
   */
  private attributeWrite(path: string): void {
    if (!this.pluginSettingsComponent.settings.needsCreatingPluginAttribution()) {
      return;
    }

    if (extname(path).toLowerCase() === NOTE_FILE_EXTENSION) {
      return;
    }

    const pluginId = findCreatingPluginId(captureStackTrace(), this.pluginId);
    if (pluginId === null) {
      return;
    }

    foreignWriteRegistry.register(path, pluginId);
  }
}
