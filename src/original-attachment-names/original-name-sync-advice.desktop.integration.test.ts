/**
 * @file
 *
 * The storage page tells a device whose Obsidian Sync has no remote vault that synchronization is not needed, and refuses
 * the Obsidian Sync setup there instead of showing its checklist. That is the common real case: Obsidian turns the core
 * Sync plugin on by default, so it is enabled in the test vault, with no account and no remote vault.
 *
 * It also proves the premise of `obsidian-sync-status.ts` against the real core Sync plugin: the remote-vault getter and
 * the selective-sync filter it reads are where it expects them. The test vault never connects a remote vault, so the
 * connected branch is covered by the unit tests only.
 */

import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  expect,
  it
} from 'vitest';

it('explains that a device without Obsidian Sync needs no synchronization, and refuses the Obsidian Sync setup there', async () => {
  const vaultPath = getTemporaryVault().path;
  const result = await evalInObsidian({
    async callback({ app, lib: { clickElement, waitUntil } }) {
      const pluginId = 'obsidian-custom-attachment-location';
      const timeoutInMilliseconds = 10_000;
      const syncPlugin = app.internalPlugins.getPluginById('sync');
      const instance: unknown = syncPlugin?.instance;
      const filter: unknown = instance && Reflect.get(instance, 'filter');
      const getRemoteVaultId: unknown = instance && Reflect.get(instance, 'getRemoteVaultId');
      const allowSyncFile: unknown = filter && Reflect.get(filter, 'allowSyncFile');
      if (typeof getRemoteVaultId !== 'function' || typeof allowSyncFile !== 'function') {
        throw new TypeError('The core Sync plugin no longer has getRemoteVaultId() and filter.allowSyncFile()');
      }
      const premise = {
        // A JSON file needs `Sync all other types`, which is off by default.
        isJsonCarriedByDefault: allowSyncFile.call(filter, '@Plugin sync data (DO NOT REMOVE)/plugin/store/history.json', false) as unknown,
        isNoteCarriedByDefault: allowSyncFile.call(filter, 'note.md', false) as unknown,
        isSyncEnabled: app.internalPlugins.getEnabledPluginById('sync') !== null,
        remoteVaultId: getRemoteVaultId.call(instance) as unknown
      };

      try {
        app.setting.open();
        app.setting.openTabById(pluginId);
        const tab = app.setting.pluginTabs.find((entry) => entry.id === pluginId);
        const page = [...(tab?.containerEl.querySelectorAll<HTMLElement>('.setting-item') ?? [])].find((entry) => entry.querySelector('.setting-item-name')?.textContent === 'Original name storage');
        if (!page) {
          throw new Error('Storage page missing');
        }
        page.scrollIntoView({ block: 'center' });
        await clickElement({ element: page });
        await waitUntil({ message: 'The storage page must show its setup actions', predicate: () => [...document.querySelectorAll('button')].some((entry) => entry.textContent === 'Set up Obsidian Sync'), timeoutInMilliseconds });
        const advice = document.querySelector('.original-name-storage-advice')?.textContent ?? '';
        const button = [...document.querySelectorAll('button')].find((entry) => entry.textContent === 'Set up Obsidian Sync');
        if (!button) {
          throw new Error('Obsidian Sync setup action missing');
        }
        button.scrollIntoView({ block: 'center' });
        await clickElement({ element: button });
        await waitUntil({
          message: 'The Obsidian Sync setup must explain that Sync is not connected',
          predicate: () => [...document.querySelectorAll('.modal')].some((entry) => entry.textContent.includes('Obsidian Sync is not connected to a remote vault on this device')),
          timeoutInMilliseconds
        });
        const hasChecklist = [...document.querySelectorAll('.modal-title')].some((entry) => entry.textContent === 'Enable original name synchronization?');
        return { advice, hasChecklist, premise };
      } finally {
        for (const modal of document.querySelectorAll('.modal')) {
          modal.querySelector<HTMLButtonElement>('button.mod-cta, button.cancel-button')?.click();
        }
        app.setting.close();
      }
    },
    vaultPath
  });

  expect(result.premise).toEqual({ isJsonCarriedByDefault: false, isNoteCarriedByDefault: true, isSyncEnabled: true, remoteVaultId: null });
  expect(result.advice).toContain('Obsidian Sync is not connected to a remote vault on this device, so original names stay here and no folder is created');
  expect(result.hasChecklist).toBe(false);
}, 60_000);
