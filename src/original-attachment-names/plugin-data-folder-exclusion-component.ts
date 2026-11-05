/**
 * @file
 *
 * Keeps the folders that hold the synchronized original-name history out of the user's way, and explains them.
 *
 * Each folder goes into Obsidian's **Excluded files** (`userIgnoreFilters`), so its history files stay out of search,
 * the graph and the quick switcher, and gets a `README.md` that says what it is and that it must not be removed.
 *
 * The entries this plugin added are remembered per device, so a changed folder replaces only its own entry: an entry
 * the user already had is never recorded as ours, and so never removed.
 */

import type { App } from 'obsidian';

import { registerAsyncEvent } from '@mnaoumov/obsidian-lib/components/async-events-component';
import { LayoutReadyComponent } from '@mnaoumov/obsidian-lib/components/layout-ready-component';
import { invokeAsyncSafely } from '@mnaoumov/typescript-lib/async';
import { noopAsync } from '@mnaoumov/typescript-lib/function';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

const USER_IGNORE_FILTERS_CONFIG_KEY = 'userIgnoreFilters';
const MANAGED_IGNORE_FILTERS_LOCAL_STORAGE_KEY = 'obsidian-custom-attachment-location:managed-ignore-filters-v1';

/**
 * The name of the explanation file written into each store folder.
 */
export const PLUGIN_DATA_FOLDER_README_FILE_NAME = 'README.md';

/**
 * Where the README sends a user who wants the whole story.
 */
export const PLUGIN_DATA_FOLDER_DOCS_URL = 'https://mnaoumov.dev/obsidian/plugin-sync-data/';

/**
 * The text of the explanation file. Public, plain wording: it is read by whoever opens the folder.
 */
export const PLUGIN_DATA_FOLDER_README = `# Plugin sync data - do not remove

This folder holds data that Obsidian plugins keep in your vault so that it can sync between your devices.

The \`Custom Attachment Location\` plugin keeps the original names of your attachments here, in the \`obsidian-custom-attachment-location\` folder.

- Do not delete, move or rename this folder or anything in it, and do not edit these files by hand. They are history, not a cache: what is removed cannot be rebuilt.
- Keep this folder synchronized on every device that uses the vault.
- The folder is listed in Obsidian's **Settings → Files and links → Excluded files**, so it stays out of search, the graph and the quick switcher.

The plugin writes this file, so any change you make to it is lost.

Learn more: ${PLUGIN_DATA_FOLDER_DOCS_URL}
`;

interface PluginDataFolderExclusionComponentConstructorParams {
  readonly app: App;
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
}

/**
 * Keeps Excluded files in step with the store's folders, and writes their README.
 */
export class PluginDataFolderExclusionComponent extends LayoutReadyComponent {
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private reconciliation: Promise<void> = noopAsync();

  public constructor(params: PluginDataFolderExclusionComponentConstructorParams) {
    super(params.app);
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
  }

  /**
   * Brings Excluded files and the README files up to date. Serialized, so overlapping triggers never race.
   *
   * @returns Completion of this reconciliation.
   */
  public reconcile(): Promise<void> {
    const run = this.reconciliation.catch(() => undefined).then(() => this.reconcileImpl());
    this.reconciliation = run;
    return run;
  }

  protected override onLayoutReady(): void {
    const schedule = this.scheduleReconcile.bind(this);
    registerAsyncEvent(this, this.pluginSettingsComponent.on('loadSettings', schedule));
    registerAsyncEvent(
      this,
      this.pluginSettingsComponent.on('saveSettings', (newState, oldState) => {
        if (newState.effectiveValues.pluginDataFolder !== oldState.effectiveValues.pluginDataFolder) {
          schedule();
        }
      })
    );
    this.register(this.originalAttachmentNamesComponent.onStorageChanged(schedule));
    schedule();
  }

  private readManagedFilters(): string[] {
    const value: unknown = this.app.loadLocalStorage(MANAGED_IGNORE_FILTERS_LOCAL_STORAGE_KEY);
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
  }

  private async reconcileImpl(): Promise<void> {
    const existingFolders = await this.originalAttachmentNamesComponent.getExistingStoreFolders();
    const folders = [...existingFolders];
    const settingFolder = this.pluginSettingsComponent.settings.pluginDataFolder;
    // The setting names where history goes next; it matters only on a device that synchronizes.
    if (this.originalAttachmentNamesComponent.isSyncEnabled && !folders.includes(settingFolder)) {
      folders.push(settingFolder);
    }

    // Obsidian never indexes a hidden folder, so an entry for one would only be noise.
    const desiredFilters = folders.filter((folder) => folder.split('/').every((segment) => !segment.startsWith('.'))).map((folder) => `${folder}/`);
    this.updateFilters(desiredFilters);

    for (const folder of existingFolders) {
      await this.writeReadme(folder);
    }
  }

  private scheduleReconcile(): void {
    invokeAsyncSafely(() => this.reconcile());
  }

  private updateFilters(desiredFilters: readonly string[]): void {
    const managedFilters = this.readManagedFilters();
    const currentFilters = this.app.vault.getConfig(USER_IGNORE_FILTERS_CONFIG_KEY) ?? [];
    const nextFilters = currentFilters.filter((filter) => !managedFilters.includes(filter) || desiredFilters.includes(filter));
    const nextManagedFilters = managedFilters.filter((filter) => desiredFilters.includes(filter) && nextFilters.includes(filter));
    for (const filter of desiredFilters) {
      if (nextFilters.includes(filter)) {
        continue;
      }

      nextFilters.push(filter);
      nextManagedFilters.push(filter);
    }

    if (nextFilters.length !== currentFilters.length || nextFilters.some((filter, index) => filter !== currentFilters[index])) {
      this.app.vault.setConfig(USER_IGNORE_FILTERS_CONFIG_KEY, nextFilters);
    }
    this.app.saveLocalStorage(MANAGED_IGNORE_FILTERS_LOCAL_STORAGE_KEY, nextManagedFilters.length > 0 ? nextManagedFilters : null);
  }

  private async writeReadme(folder: string): Promise<void> {
    const adapter = this.app.vault.adapter;
    const path = `${folder}/${PLUGIN_DATA_FOLDER_README_FILE_NAME}`;
    if (await adapter.exists(path) && await adapter.read(path) === PLUGIN_DATA_FOLDER_README) {
      return;
    }
    await adapter.write(path, PLUGIN_DATA_FOLDER_README);
  }
}
