import type { App } from 'obsidian';

import {
  evalInObsidian,
  pollInObsidian
} from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  expect,
  it
} from 'vitest';

import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

// Relocation retains its discovery chain permanently. Dedicated desktop/Android projects give this suite
// its own vault, so no later suite inherits a hidden writer that cannot be moved back to an old root.

interface StorageSettings {
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Edited through the settings component.
  pluginDataFolder: string;
  // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- Edited through the settings component.
  shouldAllowHiddenPluginDataFolder: boolean;
}

function isStorageSettings(value: unknown): value is StorageSettings {
  return typeof value === 'object' && value !== null && 'pluginDataFolder' in value;
}

function readStorage(app: App): OriginalAttachmentNamesComponent {
  const tab = app.setting.pluginTabs.find((entry) => entry.id === 'obsidian-custom-attachment-location');
  if (!tab) {
    throw new Error('Storage settings tab missing');
  }
  const getter = Reflect.get(tab, 'getOriginalAttachmentNamesComponent') as () => OriginalAttachmentNamesComponent;
  return getter();
}

it('keeps names locally, opts in through settings, relocates to a hidden root and preserves history after reload', async () => {
  const vaultPath = getTemporaryVault().path;
  const input = { findPluginSettingsComponent, isStorageSettings, readStorage };
  const state = await evalInObsidian({
    callback({ app, findPluginSettingsComponent: findSettings, isStorageSettings: isSettings, readStorage: storage }) {
      const settings = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
      if (!settings) {
        throw new Error('Storage settings missing');
      }
      return {
        prior: { pluginDataFolder: settings.settings.pluginDataFolder, shouldAllowHiddenPluginDataFolder: settings.settings.shouldAllowHiddenPluginDataFolder },
        wasEnabled: storage(app).isSyncEnabled
      };
    },
    input,
    vaultPath
  });
  // One-core Android adapter I/O needs separate phases within the renderer's thirty-second cap.
  let phase = 'local history and consent dialog';
  let failure: Error | null = null;
  try {
    const localName = await evalInObsidian({
      async callback({ app, lib: { waitUntil }, readStorage: storage }) {
        const pluginId = 'obsidian-custom-attachment-location';
        const timeoutInMilliseconds = 8000;
        const component = storage(app);
        await component.setSyncEnabled(false);
        const file = await app.vault.createBinary('storage-alpha.pdf', new TextEncoder().encode('alpha').buffer);
        component.set(file.path, 'arrival-alpha.pdf');
        await component.flush();
        app.setting.open();
        app.setting.openTabById(pluginId);
        const tab = app.setting.pluginTabs.find((entry) => entry.id === pluginId);
        const page = [...(tab?.containerEl.querySelectorAll<HTMLElement>('.setting-item') ?? [])].find((entry) => entry.querySelector('.setting-item-name')?.textContent === 'Original name storage');
        if (!page) {
          throw new Error('Storage page missing');
        }
        page.click();
        await waitUntil({ message: 'The storage page must show its external setup action', predicate: () => [...document.querySelectorAll('button')].some((entry) => entry.textContent === 'Set up external sync'), timeoutInMilliseconds });
        const button = [...document.querySelectorAll('button')].find((entry) => entry.textContent === 'Set up external sync');
        if (!button) {
          throw new Error('External setup action missing');
        }
        button.click();
        await waitUntil({ message: 'External setup must ask for consent', predicate: () => [...document.querySelectorAll('.modal-title')].some((entry) => entry.textContent === 'Enable original name synchronization?'), timeoutInMilliseconds });
        return component.get(file.path);
      },
      input,
      vaultPath
    });
    expect(localName).toBe('arrival-alpha.pdf');
    phase = 'confirm synchronization setup';
    await evalInObsidian({
      async callback({ app, lib: { waitUntil }, readStorage: storage }) {
        const timeoutInMilliseconds = 15_000;
        const modal = [...document.querySelectorAll('.modal')].find((entry) => entry.querySelector('.modal-title')?.textContent === 'Enable original name synchronization?');
        const ok = modal?.querySelector<HTMLButtonElement>('button.mod-cta');
        if (!ok) {
          throw new Error('Setup confirmation missing');
        }
        ok.click();
        await waitUntil({ message: 'Confirmed setup must enable JSON synchronization on this device', predicate: () => storage(app).isSyncEnabled, timeoutInMilliseconds });
        await storage(app).flush();
      },
      input,
      vaultPath
    });
    phase = 'apply hidden destination';
    const location = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettings, isStorageSettings: isSettings, readStorage: storage }) {
        const pluginId = 'obsidian-custom-attachment-location';
        const destination = '99-Meta/.original-names';
        const settings = findSettings(app.plugins.getPlugin(pluginId), isSettings);
        if (!settings) {
          throw new Error('Storage settings missing');
        }
        await settings.editAndSave((draft) => {
          draft.shouldAllowHiddenPluginDataFolder = true;
          draft.pluginDataFolder = destination;
        });
        const apply = [...document.querySelectorAll('button')].find((entry) => entry.textContent === 'Apply folder');
        if (!apply) {
          throw new Error('Apply folder action missing');
        }
        apply.click();
        await storage(app).flush();
        const saved = await app.vault.adapter.list(`${destination}/${pluginId}/original-attachment-names-v1/devices`);
        return { devices: saved.folders.length, roots: [...storage(app).transportRoots] };
      },
      input,
      vaultPath
    });
    expect(location.roots).toContain('99-Meta/.original-names/obsidian-custom-attachment-location/original-attachment-names-v1');
    expect(location.devices).toBeGreaterThan(0);
    phase = 'rename and reload';
    const nameAfterReload = await evalInObsidian({
      async callback({ app, lib: { waitUntil }, readStorage: storage }) {
        const pluginId = 'obsidian-custom-attachment-location';
        const timeoutInMilliseconds = 8000;
        const file = app.vault.getFileByPath('storage-alpha.pdf');
        if (!file) {
          throw new Error('The staged attachment is missing');
        }
        await app.vault.rename(file, 'storage-bravo.pdf');
        await storage(app).flush();
        app.setting.close();
        await app.plugins.disablePlugin(pluginId);
        await app.plugins.enablePlugin(pluginId);
        await waitUntil({ message: 'Original-name commands must return after reload', predicate: () => Object.hasOwn(app.commands.commands, `${pluginId}:show-original-attachment-names`), timeoutInMilliseconds });
        return storage(app).get(file.path);
      },
      input,
      vaultPath
    });
    expect(nameAfterReload).toBe('arrival-alpha.pdf');
  } catch (error) {
    failure = new Error(`Storage phase failed: ${phase}`, { cause: error });
  } finally {
    try {
      await evalInObsidian({
        async callback({ app, findPluginSettingsComponent: findSettings, isStorageSettings: isSettings, readStorage: storage, state: priorState }) {
          const setupModal = [...document.querySelectorAll('.modal')].find((entry) => entry.querySelector('.modal-title')?.textContent === 'Enable original name synchronization?');
          setupModal?.querySelector<HTMLButtonElement>('button.cancel-button')?.click();
          app.setting.close();
          await storage(app).setSyncEnabled(priorState.wasEnabled);
          const restored = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
          await restored?.editAndSave((draft) => Object.assign(draft, priorState.prior));
          for (const path of ['storage-alpha.pdf', 'storage-bravo.pdf']) {
            const file = app.vault.getFileByPath(path);
            if (file) {
              await app.fileManager.trashFile(file);
            }
          }
        },
        input: { ...input, state },
        vaultPath
      });
    } catch (error) {
      failure ??= new Error('Storage cleanup failed', { cause: error });
    }
  }
  if (failure) {
    throw failure;
  }
}, 180_000);
it('keeps visible JSON transport history out of per-note and orphan attachment deletion', async () => {
  const vaultPath = getTemporaryVault().path;
  const state = await evalInObsidian({
    async callback({ app, findPluginSettingsComponent: findSettings, readStorage: storage }) {
      const pluginId = 'obsidian-custom-attachment-location';
      const root = `Plugin data/${pluginId}/original-attachment-names-v1`;
      type CleanupSettings = Record<'attachmentFolderPath' | 'orphanAttachmentScanMode', string>;
      function isSettings(value: unknown): value is CleanupSettings {
        return typeof value === 'object' && value !== null && 'orphanAttachmentScanMode' in value;
      }
      const settings = findSettings(app.plugins.getPlugin(pluginId), isSettings);
      if (!settings) {
        throw new Error('Storage settings missing');
      }
      const wasEnabled = storage(app).isSyncEnabled;
      const prior = { attachmentFolderPath: settings.settings.attachmentFolderPath, orphanAttachmentScanMode: settings.settings.orphanAttachmentScanMode };
      await storage(app).setSyncEnabled(true);
      const listing = await app.vault.adapter.list(`${root}/locations-v1`);
      const metadataPath = listing.files.find((path) => path.endsWith('.json'));
      if (!metadataPath) {
        throw new Error('JSON discovery history missing');
      }
      const bytesBefore = await app.vault.adapter.read(metadataPath);
      await app.vault.create('storage-cleanup.md', 'A note whose attachment folder contains plugin metadata.');
      await app.vault.create('storage-unused.pdf', 'ordinary unused attachment');
      await settings.editAndSave((draft) => {
        draft.attachmentFolderPath = 'Plugin data';
        draft.orphanAttachmentScanMode = 'Entire vault';
      });
      return { bytesBefore, metadataPath, prior, wasEnabled };
    },
    input: { findPluginSettingsComponent, readStorage },
    vaultPath
  });
  const input = { findPluginSettingsComponent, readStorage, state };
  try {
    await pollInObsidian({
      input,
      poll: ({ app, state: saved }) => app.vault.getFileByPath(saved.metadataPath) !== null,
      timeoutInMilliseconds: 15_000,
      timeoutMessage: 'Visible JSON history must be indexed before testing attachment cleanup',
      until: (isIndexed) => isIndexed,
      vaultPath
    });
    await pollInObsidian({
      poll: () => [...document.querySelectorAll('.modal-title')].some((entry) => entry.textContent.trim() === 'Delete unused attachments in file'),
      start: ({ app }) => app.commands.executeCommandById('obsidian-custom-attachment-location:delete-unused-attachments-entire-vault'),
      timeoutInMilliseconds: 15_000,
      timeoutMessage: 'The ordinary unused PDF must reach the delete confirmation',
      until: (isOpen) => isOpen,
      vaultPath
    });
    await pollInObsidian({
      poll: ({ app }) => app.vault.getFileByPath('storage-unused.pdf') === null,
      start: () => {
        const modal = [...document.querySelectorAll('.modal')].find((entry) => entry.querySelector('.modal-title')?.textContent.trim() === 'Delete unused attachments in file');
        const ok = modal?.querySelector<HTMLButtonElement>('button.mod-cta');
        if (!ok) {
          throw new Error('Delete confirmation button missing');
        }
        ok.click();
      },
      timeoutInMilliseconds: 15_000,
      timeoutMessage: 'The ordinary unused PDF must be deleted',
      until: (isDeleted) => isDeleted,
      vaultPath
    });
    const bytesAfter = await evalInObsidian({
      callback: ({ app, state: saved }) => app.vault.adapter.read(saved.metadataPath),
      input,
      vaultPath
    });
    expect(bytesAfter).toBe(state.bytesBefore);
  } finally {
    await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettings, readStorage: storage, state: saved }) {
        const modal = [...document.querySelectorAll('.modal')].find((entry) => entry.querySelector('.modal-title')?.textContent.trim() === 'Delete unused attachments in file');
        modal?.querySelector<HTMLButtonElement>('button.cancel-button')?.click();
        type CleanupSettings = Record<'attachmentFolderPath' | 'orphanAttachmentScanMode', string>;
        function isSettings(value: unknown): value is CleanupSettings {
          return typeof value === 'object' && value !== null && 'orphanAttachmentScanMode' in value;
        }
        const settings = findSettings(app.plugins.getPlugin('obsidian-custom-attachment-location'), isSettings);
        if (!settings) {
          throw new Error('Cleanup settings missing');
        }
        await settings.editAndSave((draft) => Object.assign(draft, saved.prior));
        await storage(app).setSyncEnabled(saved.wasEnabled);
        for (const path of ['storage-cleanup.md', 'storage-unused.pdf']) {
          const file = app.vault.getFileByPath(path);
          if (file) {
            await app.fileManager.trashFile(file);
          }
        }
      },
      input,
      vaultPath
    });
  }
}, 180_000);
