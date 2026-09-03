import type { Vault as VaultOriginal } from 'obsidian';

import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';

import { foreignWriteRegistry } from '../foreign-write-registry.ts';
import {
  PluginSettings,
  RenameAttachmentsCreatedByOtherPluginsMode
} from '../plugin-settings.ts';
import { WriteAttributionPatchComponent } from './write-attribution-patch-component.ts';

const OWN_PLUGIN_ID = 'custom-attachment-location';
const FOREIGN_PLUGIN_ID = 'media-extended';

type ForeignWriter = (vault: VaultOriginal) => Promise<unknown>;

/**
 * Compiles `body` under a `plugin:<id>` source URL, the way Obsidian compiles a community plugin's
 * `main.js`, so the frames it produces are indistinguishable from a real plugin's.
 *
 * @param pluginId - The id the compiled code is attributed to.
 * @param body - The function body, receiving `vault`.
 * @returns The compiled writer.
 */
function createForeignWriter(pluginId: string, body: string): ForeignWriter {
  return new Function('vault', `${body}\n//# sourceURL=plugin:${pluginId}`) as ForeignWriter;
}

describe('WriteAttributionPatchComponent', () => {
  let app: App;
  let settings: PluginSettings;
  let vault: VaultOriginal;

  beforeEach(() => {
    app = App.createConfigured__();
    vault = app.vault.asOriginalType2__();
    settings = new PluginSettings();
    settings.renameAttachmentsCreatedByOtherPluginsMode = RenameAttachmentsCreatedByOtherPluginsMode.OnlyListedPlugins;
  });

  function createComponent(): WriteAttributionPatchComponent {
    return new WriteAttributionPatchComponent({
      pluginId: OWN_PLUGIN_ID,
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({ settings }),
      vault
    });
  }

  it('should patch every write entry point a plugin can reach the disk through', () => {
    const component = createComponent();
    const registerMethodPatchSpy = vi.spyOn(component, 'registerMethodPatch');

    component.load();

    expect(registerMethodPatchSpy).toHaveBeenCalledTimes(4);
  });

  it('should attribute a binary attachment written through the vault', async () => {
    createComponent().load();
    const write = createForeignWriter(FOREIGN_PLUGIN_ID, 'return vault.createBinary("shot.png", new ArrayBuffer(4));');

    await write(vault);

    expect(foreignWriteRegistry.consume('shot.png')).toBe(FOREIGN_PLUGIN_ID);
  });

  it('should attribute a text attachment written through the vault', async () => {
    createComponent().load();
    const write = createForeignWriter(FOREIGN_PLUGIN_ID, 'return vault.create("diagram.svg", "<svg/>");');

    await write(vault);

    expect(foreignWriteRegistry.consume('diagram.svg')).toBe(FOREIGN_PLUGIN_ID);
  });

  it('should attribute a write that bypasses the vault for the adapter', async () => {
    createComponent().load();
    const write = createForeignWriter(FOREIGN_PLUGIN_ID, 'return vault.adapter.writeBinary("raw.png", new ArrayBuffer(4));');

    await write(vault);

    expect(foreignWriteRegistry.consume('raw.png')).toBe(FOREIGN_PLUGIN_ID);
  });

  it('should attribute a text write that bypasses the vault for the adapter', async () => {
    createComponent().load();
    const write = createForeignWriter(FOREIGN_PLUGIN_ID, 'return vault.adapter.write("raw.svg", "<svg/>");');

    await write(vault);

    expect(foreignWriteRegistry.consume('raw.svg')).toBe(FOREIGN_PLUGIN_ID);
  });

  it('should attribute nothing when no plugin is on the stack', async () => {
    createComponent().load();

    await vault.createBinary('core.png', new ArrayBuffer(4));

    // Obsidian core, a sync client and a raw `fs` write all land here — unattributable, not "no plugin".
    expect(foreignWriteRegistry.consume('core.png')).toBeNull();
  });

  it('should attribute nothing when the mode does not consult the plugin id', async () => {
    settings.renameAttachmentsCreatedByOtherPluginsMode = RenameAttachmentsCreatedByOtherPluginsMode.All;
    createComponent().load();
    const write = createForeignWriter(FOREIGN_PLUGIN_ID, 'return vault.createBinary("shot.png", new ArrayBuffer(4));');

    await write(vault);

    // The stack is never captured under `All` / `None`, so a user who never opts into a list pays nothing.
    expect(foreignWriteRegistry.consume('shot.png')).toBeNull();
  });

  it('should attribute nothing for a note, which is never the attachment being renamed', async () => {
    createComponent().load();
    const write = createForeignWriter(FOREIGN_PLUGIN_ID, 'return vault.create("Note.MD", "hello");');

    await write(vault);

    expect(foreignWriteRegistry.consume('Note.MD')).toBeNull();
  });

  it('should still perform the write it observes', async () => {
    createComponent().load();
    const write = createForeignWriter(FOREIGN_PLUGIN_ID, 'return vault.createBinary("shot.png", new ArrayBuffer(4));');

    await write(vault);

    expect(vault.getAbstractFileByPath('shot.png')).not.toBeNull();
  });
});
