/**
 * @file
 *
 * Remembers the name each attachment ARRIVED with, which is what `{{originalAttachmentFileName}}` means.
 *
 * Until this existed, the token read the attachment's current name. A collect template such as
 * `{{noteFileName}}-{{originalAttachmentFileName}}` therefore stacked on every collect: `img` became `Note-img`, then
 * `Note-Note-img`, because once a file was renamed its old name was gone for good.
 *
 * The record is keyed by the attachment's path and follows every rename or move the vault reports, so it survives
 * this plugin's own renames and the user's renames inside Obsidian. IndexedDB keeps local history; optional
 * transport writes JSON and reads legacy Markdown. The old plugin-folder JSON is migration input only.
 */

import type { ConsoleDebugComponent } from '@mnaoumov/obsidian-lib/components/console-debug-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type {
  App,
  Debouncer,
  ListedFiles,
  TAbstractFile
} from 'obsidian';
import type {
  Except,
  JsonValue
} from 'type-fest';

import { AllWindowsEventComponent } from '@mnaoumov/obsidian-lib/components/all-windows-event-component';
import { ComponentEx } from '@mnaoumov/obsidian-lib/components/component-ex';
import { PluginNoticeMode } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import { DataStoreLocations } from '@mnaoumov/obsidian-lib/data-stores/data-store-locations';
import { DataStoreTransport } from '@mnaoumov/obsidian-lib/data-stores/data-store-transport';
import { LocalDataStore } from '@mnaoumov/obsidian-lib/data-stores/local-data-store';
import { SharedDataStore } from '@mnaoumov/obsidian-lib/data-stores/shared-data-store';
import { appendCodeBlock } from '@mnaoumov/obsidian-lib/html-element';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { alert } from '@mnaoumov/obsidian-lib/modals/alert';
import {
  convertAsyncToSync,
  invokeAsyncSafely
} from '@mnaoumov/typescript-lib/async';
import { noopAsync } from '@mnaoumov/typescript-lib/function';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import {
  ensureNonNullable,
  isStringArray
} from '@mnaoumov/typescript-lib/type-guards';
import {
  ButtonComponent,
  debounce,
  TFile,
  TFolder
} from 'obsidian';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { ActionContext } from '../tokens/token-evaluator-context.ts';
import type { OriginalAttachmentNameOperation } from './original-attachment-name-history.ts';

import { isNonInteractiveActionContext } from '../tokens/token-evaluator-context.ts';
import {
  isRetiredSourcePathOperation,
  OriginalAttachmentNameHistory
} from './original-attachment-name-history.ts';
import {
  DEFAULT_PLUGIN_DATA_FOLDER,
  isPluginDataFolderReadme,
  LEGACY_PLUGIN_DATA_FOLDER,
  PLUGIN_DATA_FOLDER_README_FILE_NAME,
  PLUGIN_DATA_SUBFOLDER_NAME,
  validatePluginDataFolder
} from './plugin-data-folder.ts';

/**
 * The legacy JSON migration source, kept untouched inside the plugin's folder.
 */
export const ORIGINAL_ATTACHMENT_NAMES_FILE_NAME = 'original-attachment-names.json';

const STORE_ID = 'original-attachment-names-v1';
const PLUGIN_ID = 'obsidian-custom-attachment-location';
const SYNCHRONIZE_INTERVAL_IN_MILLISECONDS = 60_000;
const MIGRATION_KEY = 'original-attachment-names-json-migrated-v1';
const SYNC_CONSENT_KEY = 'original-name-sync-consent-v1';
const REQUESTED_ROOTS_KEY = 'original-name-requested-transport-roots-v1';
const SYNC_PROVIDER_KEY = 'original-name-sync-provider-v1';
const ANCHOR_FOLDER_KEY = 'original-name-anchor-folder-v1';
const PENDING_ANCHOR_FOLDER = '';
const SAVE_DEBOUNCE_IN_MILLISECONDS = 1000;
const WARNING_DEBOUNCE_IN_MILLISECONDS = 1000;
const COMPACTION_OPERATION_COUNT = 100;

/**
 * Folders the walk for moved history never enters: large, and never a home for plugin data.
 */
const SKIPPED_FOLDER_NAMES_ON_DISK = new Set(['.git', '.trash', 'node_modules']);

/**
 * How long a path handed out for a new attachment waits for the file to be created. The same minute the
 * self-write registry gives its claims: a path that is never written costs nothing once it expires.
 */
const EXPECTED_ARRIVAL_TIMEOUT_IN_MILLISECONDS = 60_000;

/**
 * One remembered arrival name.
 */
export interface OriginalAttachmentNameRecord {
  /**
   * Whether no file exists at {@link path} any more.
   */
  readonly isMissing: boolean;

  /**
   * The name the attachment arrived with, extension included.
   */
  readonly originalFileName: string;

  /**
   * The attachment's current path.
   */
  readonly path: string;
}

/**
 * Parameters for {@link OriginalAttachmentNamesComponent.reportUnknown}.
 */
export interface OriginalAttachmentNamesComponentReportUnknownParams {
  /**
   * The action the name was needed for.
   */
  readonly actionContext: ActionContext;

  /**
   * The name used instead, extension included.
   */
  readonly currentFileName: string;

  /**
   * The attachment's path.
   */
  readonly path: string;
}

interface ExpectedArrival {
  readonly expiresAt: number;
  readonly fileName: string;
}

interface FoundAnchor {
  readonly canOpen: boolean;
  readonly folder: string;
}

interface OriginalAttachmentNamesComponentConstructorParams {
  readonly app: App;
  readonly consoleDebugComponent: ConsoleDebugComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly storeFilePath: string;
}

/**
Options for explicitly enabling synchronization on this device.
*/
interface OriginalAttachmentNamesComponentSetSyncEnabledOptions {
  /**
   * Whether setup must refuse history roots that Obsidian Sync cannot carry.
   *
   * @default `false`
   */
  readonly shouldUseObsidianSync?: boolean;
}

/**
 * One side of a relocation record that `DataStoreLocations` writes under the anchor's `locations-v1` folder.
 */
interface RelocationLocation {
  readonly folder: string;
}

interface RelocationRecord {
  /**
   * The anchor folder the record was written at. Records written before `obsidian-lib` 11 have none.
   */
  readonly anchor?: RelocationLocation;
  readonly from: RelocationLocation;
  readonly to: RelocationLocation;
}

interface StoredOriginalAttachmentNames {
  readonly names: Record<string, string>;
  readonly version: number;
}

/**
 * Keeps the arrival name of every attachment this plugin has seen arrive, keyed by its current path.
 */
export class OriginalAttachmentNamesComponent extends ComponentEx {
  /**
   * Whether this device's synchronization was set up for Obsidian Sync, rather than an external sync tool.
   */
  public get isObsidianSyncProvider(): boolean {
    return this.shouldUseObsidianSync;
  }

  /**
  Whether this device has enabled cross-device transport.
  */
  public get isSyncEnabled(): boolean {
    return this.syncEnabled;
  }

  /**
   * How many records there are.
   *
   * @returns The count.
   */
  public get size(): number {
    return this.names.size;
  }

  /**
  Active and retained transport roots, including the permanent discovery anchor.
  */
  public get transportRoots(): readonly string[] {
    return [...new Set([...(this.shared?.transportRoots ?? []), ...this.requestedTransportRoots])];
  }

  private anchorFolder = DEFAULT_PLUGIN_DATA_FOLDER;
  private readonly app: App;
  /**
   * Where the anchor's history was moved to, when this version cannot follow it there. Transport is paused meanwhile,
   * because writing at the old anchor would start a second, split history.
   */
  private blockedMovedAnchorFolder: string | undefined;
  private readonly consoleDebugComponent: ConsoleDebugComponent;
  private readonly expectedArrivals = new Map<string, ExpectedArrival>();

  private hasApprovedSyncSetup = false;
  private readonly history = new OriginalAttachmentNameHistory();
  /**
   * Set once the local store is closed for good: after a failed load, or after the final flush on unload.
   */
  private isClosed = false;
  private local: LocalDataStore | undefined;
  private readonly names = this.history.names;
  private readonly pending = new Map<string, JsonValue>();
  private persistence: Promise<void> = noopAsync();
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private publishedSinceCompaction = 0;
  private readonly renamedTransportRoots = new Set<string>();
  private readonly requestedTransportRoots = new Set<string>();
  private readonly saveDebounced: Debouncer<[], void>;
  private shared: SharedDataStore | undefined;
  private shouldUseObsidianSync = false;
  private readonly showWarningDebounced: Debouncer<[], void>;
  private readonly storageChangedCallbacks = new Set<() => void>();
  private readonly storeFilePath: string;
  private syncEnabled = false;
  private readonly unknownPaths = new Set<string>();

  public constructor(params: OriginalAttachmentNamesComponentConstructorParams) {
    super();
    this.app = params.app;
    this.consoleDebugComponent = params.consoleDebugComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.pluginSettingsComponent = params.pluginSettingsComponent;
    this.storeFilePath = params.storeFilePath;
    this.saveDebounced = debounce(
      () => {
        if (this.isStoreClosed()) {
          return;
        }
        invokeAsyncSafely(() => this.flush());
      },
      SAVE_DEBOUNCE_IN_MILLISECONDS,
      true
    );
    /*
     * Debounced rather than shown per call: one collect over a folder asks for dozens of names, and the warning
     * must be ONE notice per operation, never one per file. The quiet period is what ends an operation.
     */
    this.showWarningDebounced = debounce(
      () => {
        this.showWarning();
      },
      WARNING_DEBOUNCE_IN_MILLISECONDS,
      true
    );
  }

  /**
   * Waits for a new attachment to be created at a path this plugin handed out, and records its arrival name once it
   * is.
   *
   * A core save flow (the audio recorder, a mobile share import) asks for a path and writes the file itself, so the
   * name it asked with is known here before the file exists.
   *
   * @param path - The path handed out.
   * @param fileName - The name the attachment arrives with, extension included.
   */
  public expectArrival(path: string, fileName: string): void {
    this.expectedArrivals.set(path, {
      expiresAt: Date.now() + EXPECTED_ARRIVAL_TIMEOUT_IN_MILLISECONDS,
      fileName
    });
  }

  /**
   * Publishes pending records and merges delivered records. Failed publications remain pending for retry.
   *
   * @returns Completion of the serialized persistence operation.
   */
  public flush(): Promise<void> {
    const run = this.persistence.catch(() => undefined).then(() => this.flushImpl());
    this.persistence = run;
    return run;
  }

  /**
   * Forgets the given records, so their attachments fall back to their current names, with the warning.
   *
   * @param paths - The attachments' paths.
   * @returns How many records were removed.
   */
  public forget(paths: readonly string[]): number {
    let count = 0;
    for (const path of paths) {
      if (!this.names.has(path)) {
        continue;
      }

      this.record({ kind: 'remove', path });
      count++;
    }
    if (count > 0) {
      this.saveDebounced();
    }
    return count;
  }

  /**
   * Forgets every record.
   *
   * @returns How many records were removed.
   */
  public forgetAll(): number {
    const paths = new Set(this.names.keys());
    const count = paths.size;
    for (const path of paths) {
      this.record({ kind: 'remove', path });
    }
    if (count > 0) {
      this.saveDebounced();
    }
    return count;
  }

  /**
   * The name an attachment arrived with.
   *
   * @param path - The attachment's path.
   * @returns The name, extension included, or `undefined` when it is not known.
   */
  public get(path: string): string | undefined {
    return this.names.get(path);
  }

  /**
   * The parent folders of the store's history locations that exist in the vault: the anchor and every location a
   * relocation used.
   *
   * @returns The folders, vault-relative, in transition order.
   */
  public async getExistingStoreFolders(): Promise<string[]> {
    // Every root is `<folder>/<plugin id>/<store id>`, and the roots are unique, so their folders are too.
    const suffix = `/${PLUGIN_ID}/${STORE_ID}`;
    const folders: string[] = [];
    for (const root of this.transportRoots) {
      if (await this.app.vault.adapter.exists(root)) {
        folders.push(root.slice(0, -suffix.length));
      }
    }
    return folders;
  }

  /**
   * Every record, sorted by path.
   *
   * @returns The records.
   */
  public getRecords(): OriginalAttachmentNameRecord[] {
    return Array.from(this.names, ([path, originalFileName]) => ({
      isMissing: this.app.vault.getFileByPath(path) === null,
      originalFileName,
      path
    })).sort((a, b) => a.path.localeCompare(b.path));
  }

  /**
   * Whether a path is store metadata or one of its ancestor folders, including retained and attempted roots.
   *
   * @param path - Vault-relative path to protect from attachment operations.
   * @returns Whether the path intersects transport history.
   */
  public isTransportPath(path: string): boolean {
    return (this.shared?.containsTransportPath(path) ?? false)
      || [...this.renamedTransportRoots, ...this.requestedTransportRoots].some((root) => path === root || path.startsWith(`${root}/`) || root.startsWith(`${path}/`));
  }

  /**
   * Reads the records from disk. Called once, before anything asks for a name.
   */
  public async loadFromDisk(): Promise<void> {
    this.local = await LocalDataStore.open({ pluginId: PLUGIN_ID, storeId: STORE_ID, vaultId: this.app.appId });
    try {
      // A pre-existing device replica is durable evidence of the old always-enabled store. A synced
      // settings file or a partially downloaded folder alone must never enroll a new device.
      const localEntries = await this.local.entries();
      const hasLocalHistory = localEntries.length > 0;
      this.syncEnabled = await this.local.getOrCreate(SYNC_CONSENT_KEY, hasLocalHistory) === true;
      const provider = await this.local.get(SYNC_PROVIDER_KEY);
      this.hasApprovedSyncSetup = provider === 'obsidian' || provider === 'external';
      this.shouldUseObsidianSync = provider === 'obsidian';
      const requestedRoots = await this.local.get(REQUESTED_ROOTS_KEY);
      if (requestedRoots !== undefined) {
        if (!isStringArray(requestedRoots)) {
          throw new Error('Invalid requested original-name transport roots.');
        }
        for (const root of requestedRoots) {
          this.requestedTransportRoots.add(root);
        }
      }
      if (await this.local.get(ANCHOR_FOLDER_KEY) === undefined) {
        // Every earlier version wrote its history under the legacy folder, so its replica keeps that anchor.
        await this.local.set(ANCHOR_FOLDER_KEY, hasLocalHistory ? LEGACY_PLUGIN_DATA_FOLDER : PENDING_ANCHOR_FOLDER);
      }
      this.anchorFolder = await this.resolveAnchorFolder(false);
      this.shared = await this.openShared();
      this.showMovedAnchorBlockedNotice();
      await this.deleteRetiredSourcePaths(this.shared);
      this.history.merge(this.shared.entries());
      await this.migrateLegacy();
    } catch (error) {
      /*
       * The component stays loaded after a failed load, so its interval, `visibilitychange` and vault listeners keep
       * scheduling flushes. Dropping both stores makes each of those a no-op instead of a call on a closed connection.
       */
      this.local.close();
      this.local = undefined;
      this.shared = undefined;
      this.isClosed = true;
      throw error;
    }
  }

  public override onload(): void {
    super.onload();
    this.registerEvent(this.app.vault.on('create', this.handleCreate.bind(this)));
    this.registerEvent(this.app.vault.on('rename', this.handleRename.bind(this)));
    this.registerEvent(this.app.vault.on('delete', this.handleDelete.bind(this)));
    const synchronize = (): void => {
      this.saveDebounced();
    };
    const onTransportChange = (path: string): void => {
      const name = path.slice(path.lastIndexOf('/') + 1);
      if (this.isTransportPath(path) && /\.(?:md|json)$/.test(name) && (name.startsWith('log-') || name.startsWith('snapshot-') || path.includes('/locations-v1/'))) {
        synchronize();
      }
    };
    this.registerEvent(this.app.vault.on('raw', onTransportChange));
    this.registerInterval(window.setInterval(synchronize, SYNCHRONIZE_INTERVAL_IN_MILLISECONDS));
    // Any window of the app coming back into view is the app coming to the foreground.
    this.addChild(new AllWindowsEventComponent(this.app)).registerAllDocumentsDomEvent({
      callback: ($event) => {
        if (castTo<Document>($event.target).visibilityState === 'visible') {
          synchronize();
        }
      },
      type: 'visibilitychange'
    });
  }

  /**
   * Calls back after this device's storage changed: synchronization turned on or off, or the folder applied.
   *
   * @param callback - The callback.
   * @returns A function that stops the callbacks.
   */
  public onStorageChanged(callback: () => void): () => void {
    this.storageChangedCallbacks.add(callback);
    return () => {
      this.storageChangedCallbacks.delete(callback);
    };
  }

  public override onunload(): void {
    super.onunload();
    this.storageChangedCallbacks.clear();
    this.showWarningDebounced.cancel();
    // A record changed in the last second would otherwise be lost with the plugin.
    this.saveDebounced.cancel();
    invokeAsyncSafely(async () => {
      try {
        await this.flush();
      } finally {
        // A rename or collect that finishes after unload still calls `set`, which re-arms the debounce.
        this.isClosed = true;
        this.local?.close();
      }
    });
  }

  /**
   * Removes the records whose path no longer exists in the vault — a file deleted or moved outside Obsidian.
   *
   * @returns The records removed.
   */
  public prune(): OriginalAttachmentNameRecord[] {
    const staleRecords = this.getRecords().filter((record) => record.isMissing);
    this.forget(staleRecords.map((record) => record.path));
    return staleRecords;
  }

  /**
   * Moves the history to another folder, so it is kept in that folder alone.
   *
   * The store's folder is moved, not copied: every other device finds it at its new place by itself, because the
   * history is then in exactly one folder (see `resolveAnchorFolder`). A store that an earlier version relocated by
   * copying is held in several folders; the library's refresh has already copied every older folder's history into the
   * newest one, so that one is moved and the others are sent to the trash, the discovery anchor last. Settings changes
   * alone never move the store.
   *
   * @param folder - Vault-relative parent of this plugin's store.
   */
  public async relocate(folder: string): Promise<void> {
    const error = validatePluginDataFolder(folder, this.pluginSettingsComponent.settings.shouldAllowHiddenPluginDataFolder);
    if (error) {
      throw new Error(error);
    }
    const run = this.persistence.catch(() => undefined).then(async () => {
      await this.flushImpl();
      if (!this.shared || !this.syncEnabled) {
        throw new Error(t(($) => $.originalAttachmentNames.storage.enableBeforeRelocating));
      }
      if (!this.hasApprovedSyncSetup) {
        throw new Error(t(($) => $.originalAttachmentNames.storage.completeSetupBeforeRelocating));
      }
      if (this.shouldUseObsidianSync && folder.split('/').some((segment) => segment.startsWith('.'))) {
        throw new Error(t(($) => $.originalAttachmentNames.storage.hiddenObsidianSync));
      }
      // An interrupted copy may leave metadata in its target before the library activates the writer.
      // Remember exclusions first, including across a disabled restart; this never changes discovery.
      this.requestedTransportRoots.add(getOriginalNameTransportRoot(folder));
      await ensureNonNullable(this.local).set(REQUESTED_ROOTS_KEY, [...this.requestedTransportRoots]);
      await this.moveStore(folder);
      // `moveStore` reopened the store at the destination.
      this.history.merge(this.shared.entries());
    });
    this.persistence = run;
    await run;
    this.notifyStorageChanged();
  }

  /**
   * Reports that a template read the original name of an attachment that has none on record, so its current name
   * was used.
   *
   * The current name is then recorded, so every later operation builds on the same name rather than on whatever
   * the file is called by then. The user is warned once per operation, unless the setting is off or the action has
   * nobody to warn.
   *
   * @param params - The attachment and the name used instead.
   */
  public reportUnknown(params: OriginalAttachmentNamesComponentReportUnknownParams): void {
    this.consoleDebugComponent.consoleDebug(`The original name of '${params.path}' is unknown, so its current name '${params.currentFileName}' was used.`);

    // A read through the published API answers a question; it neither changes the store nor raises a notice.
    if (isNonInteractiveActionContext(params.actionContext)) {
      return;
    }

    if (!this.names.has(params.path)) {
      this.set(params.path, params.currentFileName);
    }

    if (!this.pluginSettingsComponent.settings.shouldWarnWhenOriginalAttachmentNameIsUnknown) {
      return;
    }

    this.unknownPaths.add(params.path);
    this.showWarningDebounced();
  }

  /**
   * Records an arrival, or an explicit correction when the path already has a name.
   *
   * @param path - The attachment's path.
   * @param fileName - The name, extension included.
   */
  public set(path: string, fileName: string): void {
    if (this.names.get(path) === fileName) {
      return;
    }
    this.record({ fileName, kind: this.names.has(path) ? 'edit' : 'arrival', path });
    this.saveDebounced();
  }

  /**
   * Changes this device's consent, retaining its full local history and all existing transport files.
   *
   * @param isEnabled - Whether to synchronize this device.
   * @param options - Provider requirements checked before transport starts.
   */
  public async setSyncEnabled(isEnabled: boolean, options?: OriginalAttachmentNamesComponentSetSyncEnabledOptions): Promise<void> {
    const run = this.persistence.catch(() => undefined).then(async () => {
      if (isEnabled) {
        await this.flushImpl();
      }
      let shared = this.shared;
      const local = this.local;
      if (!shared || !local) {
        throw new Error('Original attachment names are not loaded.');
      }
      // Persist disabling first: a crash must not turn transport back on. Enabling is committed only
      // after its initial synchronization succeeds, so a failed setup is retried explicitly.
      if (!isEnabled) {
        await local.set(SYNC_CONSENT_KEY, false);
      }
      try {
        if (isEnabled) {
          // Keep the legacy anchor identity on every device. The public coordinator announces JSON
          // before an initially disabled store publishes anything, so fresh setup creates no Markdown.
          // Existing enabled devices keep Markdown until the user approves this explicit transition.
          const anchorFolder = await this.resolveAnchorFolder(true);
          if (this.blockedMovedAnchorFolder !== undefined) {
            throw new Error(t(($) => $.originalAttachmentNames.storage.movedHistoryCannotBeFollowed, {
              folder: this.blockedMovedAnchorFolder,
              previousFolder: anchorFolder
            }));
          }
          if (anchorFolder !== this.anchorFolder) {
            // The vault delivered an earlier version's history after this device opened; join it instead.
            this.anchorFolder = anchorFolder;
            shared = await this.openShared();
            this.shared = shared;
          }
          const locations = new DataStoreLocations({ adapter: this.app.vault.adapter, folder: this.anchorFolder, format: 'markdown', pluginId: PLUGIN_ID, storeId: STORE_ID });
          await locations.refresh();
          for (const transport of locations.transports) {
            this.requestedTransportRoots.add(transport.root);
          }
          await local.set(REQUESTED_ROOTS_KEY, [...this.requestedTransportRoots]);
          if (options?.shouldUseObsidianSync && locations.transports.some((transport) => transport.root.split('/').some((segment) => segment.startsWith('.')))) {
            throw new Error(t(($) => $.originalAttachmentNames.storage.hiddenObsidianSync));
          }
          const active = ensureNonNullable(locations.transports.at(-1));
          if (active.extension !== '.json') {
            const suffix = `/${PLUGIN_ID}/${STORE_ID}`;
            await locations.relocate({ folder: active.root.slice(0, -suffix.length), format: 'json' });
          }
        }
        await shared.setSyncEnabled(isEnabled);
        await local.set(SYNC_CONSENT_KEY, isEnabled);
        if (isEnabled) {
          // Fixed only once transport works: from now on this device writes under this anchor for good.
          await local.set(ANCHOR_FOLDER_KEY, this.anchorFolder);
          await local.set(SYNC_PROVIDER_KEY, options?.shouldUseObsidianSync ? 'obsidian' : 'external');
          this.hasApprovedSyncSetup = true;
          this.shouldUseObsidianSync = options?.shouldUseObsidianSync === true;
        }
        this.syncEnabled = isEnabled;
        this.history.merge(shared.entries());
        if (!isEnabled) {
          await this.flushImpl();
        }
      } catch (error) {
        await shared.setSyncEnabled(false);
        await local.set(SYNC_CONSENT_KEY, false);
        this.syncEnabled = false;
        throw error;
      }
    });
    this.persistence = run;
    await run;
    this.notifyStorageChanged();
  }

  /**
   * Tells whether history found at a folder other than this device's anchor can be opened there.
   *
   * History with no relocation record always can. A record that has not fully arrived cannot be opened until it does.
   * Otherwise the library decides: it follows records that name the anchor they were written at, and infers the former
   * folder of older records only when exactly one folder completes the chain and no longer holds the store. Its own
   * discovery is asked rather than repeated here, so the two cannot disagree. On success it finishes any copy a
   * relocation left incomplete, which opening the store there does anyway.
   *
   * @param folder - The folder holding the history.
   * @param records - Its relocation records, `null` for each one that has not fully arrived.
   * @returns Whether it can be opened.
   */
  private async canOpenAnchor(folder: string, records: readonly (null | RelocationRecord)[]): Promise<boolean> {
    if (records.length === 0) {
      return true;
    }
    if (records.includes(null)) {
      return false;
    }
    try {
      await new DataStoreLocations({ adapter: this.app.vault.adapter, folder, format: 'markdown', pluginId: PLUGIN_ID, storeId: STORE_ID }).refresh();
      return true;
    } catch (error) {
      this.consoleDebugComponent.consoleDebug(`Original name history at '${folder}' cannot be opened there.`, error);
      return false;
    }
  }

  /**
   * Deletes the source-path observations 17.1.0 recorded, so the paths stop syncing between devices.
   *
   * @param shared - The opened shared store.
   */
  private async deleteRetiredSourcePaths(shared: SharedDataStore): Promise<void> {
    for (const [key, value] of shared.entries()) {
      if (isRetiredSourcePathOperation(value)) {
        await shared.delete(key);
      }
    }
  }

  /**
   * Finds this store's anchor in a vault folder other than the given one.
   *
   * Every folder holding the store is a candidate. A relocation destination holds it too, so the destinations named
   * by the candidates' relocation records are set aside, and exactly one candidate must remain. Whether that one can
   * be opened is `canOpenAnchor`'s answer.
   *
   * @param excludedFolder - The anchor folder whose history is gone.
   * @param shouldScanFileSystem - Whether to look through the file system rather than the vault index, which misses
   *   folders that an exclusion plugin hides, the usual home of plugin data.
   * @returns The anchor found and whether it can be opened, or `undefined` when there is none or more than one.
   */
  private async findAnchorElsewhere(excludedFolder: string, shouldScanFileSystem: boolean): Promise<FoundAnchor | undefined> {
    const suffix = `/${PLUGIN_ID}/${STORE_ID}`;
    const storeFolders = shouldScanFileSystem
      ? await this.listStoreFoldersOnDisk(suffix)
      : this.app.vault.getAllFolders().map((folder) => folder.path).filter((path) => path.endsWith(suffix));
    const candidates = storeFolders
      .map((path) => path.slice(0, -suffix.length))
      .filter((folder) => folder !== excludedFolder);
    const recordsByFolder = new Map<string, (null | RelocationRecord)[]>();
    for (const folder of candidates) {
      recordsByFolder.set(folder, await this.readRelocationRecords(folder));
    }
    /*
     * Records name absolute folders, so a destination inside a moved anchor is named at its old place. Map it onto the
     * candidate holding the records: by the anchor a record names, or, for a record written before records named it,
     * from the anchor this device knew, which is the folder the history left.
     */
    const destinations = new Set<string>();
    for (const [folder, records] of recordsByFolder) {
      for (const record of records) {
        if (record === null) {
          continue;
        }
        const destination = remapToMovedAnchor(record.to.folder, record.anchor?.folder ?? excludedFolder, folder);
        // A format switch stays in the folder that records it, which is never a destination of its own records.
        if (destination !== folder) {
          destinations.add(destination);
        }
      }
    }
    const anchors = candidates.filter((folder) => !destinations.has(folder));
    if (anchors.length !== 1) {
      if (anchors.length > 1) {
        this.consoleDebugComponent.consoleDebug(`Original name history was found in several folders, so none is followed: ${anchors.join(', ')}.`);
      }
      return undefined;
    }
    const folder = ensureNonNullable(anchors[0]);
    return { canOpen: await this.canOpenAnchor(folder, ensureNonNullable(recordsByFolder.get(folder))), folder };
  }

  private async flushImpl(): Promise<void> {
    let shared = this.shared;
    if (!shared || this.isStoreClosed()) {
      return;
    }
    if (this.syncEnabled) {
      shared = await this.followMovedAnchor(shared);
    }
    const batch = [...this.pending];
    if (batch.length > 0) {
      await shared.setMany(batch);
      for (const [key] of batch) {
        this.pending.delete(key);
      }
      this.publishedSinceCompaction += batch.length;
    } else {
      await shared.synchronize();
    }
    this.history.merge(shared.entries());
    if (this.publishedSinceCompaction < COMPACTION_OPERATION_COUNT) {
      return;
    }

    await shared.compact();
    this.publishedSinceCompaction = 0;
  }

  /**
   * Re-resolves the anchor before transport writes, so a move of its folder made while the plugin runs, here or on
   * another device, is followed instead of recreating the old folder.
   *
   * @param shared - The store opened at the current anchor.
   * @returns The store to use from now on.
   */
  private async followMovedAnchor(shared: SharedDataStore): Promise<SharedDataStore> {
    const previousBlock = this.blockedMovedAnchorFolder;
    const anchorFolder = await this.resolveAnchorFolder(false);
    if (anchorFolder !== this.anchorFolder) {
      this.anchorFolder = anchorFolder;
      this.requestedTransportRoots.add(getOriginalNameTransportRoot(anchorFolder));
      await ensureNonNullable(this.local).set(REQUESTED_ROOTS_KEY, [...this.requestedTransportRoots]);
      const reopened = await this.openShared();
      this.shared = reopened;
      this.notifyStorageChanged();
      return reopened;
    }
    if (previousBlock !== this.blockedMovedAnchorFolder) {
      await shared.setSyncEnabled(this.blockedMovedAnchorFolder === undefined);
      this.showMovedAnchorBlockedNotice();
    }
    return shared;
  }

  private handleCreate(file: TAbstractFile): void {
    const expectedArrival = this.expectedArrivals.get(file.path);
    if (!expectedArrival) {
      return;
    }

    this.expectedArrivals.delete(file.path);
    if (file instanceof TFile && expectedArrival.expiresAt >= Date.now()) {
      this.set(file.path, expectedArrival.fileName);
    }
  }

  private handleDelete(file: TAbstractFile): void {
    if (this.isTransportPath(file.path)) {
      if (file instanceof TFolder) {
        const attachmentPaths = [...this.names.keys()].filter((path) => path.startsWith(`${file.path}/`) && !this.isTransportPath(path));
        for (const path of attachmentPaths) {
          this.record({ kind: 'remove', path });
          this.saveDebounced();
        }
      }
      return;
    }
    this.record({ isFolder: file instanceof TFolder, kind: 'remove', path: file.path });
    this.saveDebounced();
  }

  private handleRename(file: TAbstractFile, oldPath: string): void {
    if (file instanceof TFolder) {
      // A manual folder move is not a store relocation, but its descendants are still metadata during
      // this event batch. A later delete must not publish a spurious attachment observation for it.
      for (const root of [...this.transportRoots, ...this.renamedTransportRoots]) {
        if (!(root === oldPath || root.startsWith(`${oldPath}/`))) {
          continue;
        }

        this.renamedTransportRoots.add(`${file.path}${root.slice(oldPath.length)}`);
        // The next flush follows a moved anchor; make it soon, before anything is written at the old path.
        this.saveDebounced();
      }
    }
    if (this.isTransportPath(file.path) || this.isTransportPath(oldPath)) {
      if (file instanceof TFolder) {
        const attachmentPaths = [...this.names.keys()].filter((path) => path.startsWith(`${oldPath}/`) && !this.isTransportPath(path));
        for (const path of attachmentPaths) {
          this.record({ kind: 'rename', path, target: `${file.path}${path.slice(oldPath.length)}` });
          this.saveDebounced();
        }
      }
      return;
    }
    this.record({ isFolder: file instanceof TFolder, kind: 'rename', path: oldPath, target: file.path });
    this.saveDebounced();
  }

  /**
   * Tells whether the local store can no longer be used: this component closed it, or the browser did (a
   * `versionchange` from another connection, or the forced `close` event), which the component cannot observe itself.
   *
   * @returns `true` when a flush must not touch the stores.
   */
  private isStoreClosed(): boolean {
    return this.isClosed || this.local?.isClosed === true;
  }

  /**
   * Lists the vault's store folders straight from the file system.
   *
   * The vault index holds only what Obsidian indexes, and an exclusion plugin can hide a folder from it entirely, so
   * a history moved into such a folder would never be found there. Other hidden folders are walked, because **Apply
   * folder** may move the history into one when hidden folders are allowed. The configuration folder, `.git`, `.trash`
   * and `node_modules` are skipped, and so is each store's own content.
   *
   * @param suffix - The path suffix every store folder ends with.
   * @returns The store folders' paths.
   */
  private async listStoreFoldersOnDisk(suffix: string): Promise<string[]> {
    const adapter = this.app.vault.adapter;
    const storeFolders: string[] = [];
    const pending = [''];
    for (let folder = pending.pop(); folder !== undefined; folder = pending.pop()) {
      let listed: ListedFiles;
      try {
        listed = await adapter.list(folder);
      } catch {
        // A folder removed mid-walk holds nothing to find.
        continue;
      }
      for (const child of listed.folders) {
        // Adapters differ on whether a root listing is prefixed with a slash.
        const path = child.replace(/^\/+/, '');
        const name = path.slice(path.lastIndexOf('/') + 1);
        if (SKIPPED_FOLDER_NAMES_ON_DISK.has(name) || path === this.app.vault.configDir) {
          continue;
        }
        if (path.endsWith(suffix)) {
          storeFolders.push(path);
          continue;
        }
        pending.push(path);
      }
    }
    return storeFolders.sort((a, b) => a.localeCompare(b));
  }

  private async migrateLegacy(): Promise<void> {
    const local = this.local;
    const shared = this.shared;
    if (!local || !shared || await local.get(MIGRATION_KEY) === true) {
      return;
    }
    const adapter = this.app.vault.adapter;
    if (!await adapter.exists(this.storeFilePath)) {
      return;
    }

    let stored: unknown;
    try {
      stored = JSON.parse(await adapter.read(this.storeFilePath));
    } catch (error) {
      // A damaged file must not stop the plugin loading. Every name then falls back to the current one, with the warning.
      console.error(`Could not read '${this.storeFilePath}'. Original attachment names are unknown until it is rewritten.`, error);
      return;
    }

    if (!isStoredOriginalAttachmentNames(stored)) {
      console.error(`'${this.storeFilePath}' is not a store of original attachment names. Ignoring it.`);
      return;
    }

    for (const [path, fileName] of Object.entries(stored.names)) {
      if (typeof fileName !== 'string') {
        continue;
      }

      const operation: OriginalAttachmentNameOperation = { fileName, kind: 'arrival', path, time: 0 };
      this.pending.set(JSON.stringify(['legacy', path, fileName]), { ...operation });
    }
    await this.flush();
    await local.set(MIGRATION_KEY, true);
  }

  /**
   * Moves the store's folder to the destination, gathering a store that earlier versions copied into several folders.
   *
   * @param folder - Vault-relative parent of the destination store.
   */
  private async moveStore(folder: string): Promise<void> {
    const adapter = this.app.vault.adapter;
    const local = ensureNonNullable(this.local);
    // Refreshing copies every older folder's history into the newest one, and refuses a chain that has not fully arrived.
    const locations = new DataStoreLocations({ adapter, folder: this.anchorFolder, format: 'markdown', pluginId: PLUGIN_ID, storeId: STORE_ID });
    await locations.refresh();
    const transports = locations.transports;
    const active = ensureNonNullable(transports.at(-1));
    const roots = [...new Set(transports.map((transport) => transport.root))];
    const destinationRoot = getOriginalNameTransportRoot(folder);
    if (roots.length === 1 && active.root === destinationRoot) {
      return;
    }
    if (roots.some((root) => destinationRoot.startsWith(`${root}/`) || root.startsWith(`${destinationRoot}/`))) {
      throw new Error(t(($) => $.originalAttachmentNames.storage.destinationInsideHistory, { folder }));
    }
    if (!roots.includes(destinationRoot) && await adapter.exists(destinationRoot)) {
      throw new Error(t(($) => $.originalAttachmentNames.storage.destinationOccupied, { folder }));
    }

    const anchorRoot = ensureNonNullable(roots[0]);
    const retiredRoots = roots.filter((root) => root !== active.root);
    // The vault reports the move and the trashing later; their events are about store metadata, not attachments.
    for (const root of roots) {
      if (root !== destinationRoot) {
        this.renamedTransportRoots.add(root);
      }
    }
    if (active.root !== destinationRoot) {
      if (retiredRoots.includes(destinationRoot)) {
        // A folder used before: its history is already in the newest folder, which takes its place.
        await this.trashPath(destinationRoot);
      }
      const parent = destinationRoot.slice(0, destinationRoot.lastIndexOf('/'));
      if (!await adapter.exists(parent)) {
        await adapter.mkdir(parent);
      }
      await adapter.rename(active.root, destinationRoot);
    }
    if (roots.length > 1 && active.extension === '.json') {
      /*
       * A folder a relocation copied into holds no relocation records of its own, so record its switch to JSON there.
       * Otherwise the store would reopen at it writing Markdown.
       */
      await new DataStoreLocations({ adapter, folder, format: 'markdown', pluginId: PLUGIN_ID, storeId: STORE_ID }).relocate({ folder, format: 'json' });
    }
    this.anchorFolder = folder;
    await local.set(ANCHOR_FOLDER_KEY, folder);

    // The anchor goes last: until then, a device that opens it still finds where the history went.
    const trashOrder = [...retiredRoots.filter((retiredRoot) => retiredRoot !== anchorRoot), ...retiredRoots.filter((retiredRoot) => retiredRoot === anchorRoot)];
    for (const root of trashOrder) {
      if (root !== destinationRoot && await adapter.exists(root)) {
        await this.trashPath(root);
      }
    }
    const suffix = `/${PLUGIN_ID}/${STORE_ID}`;
    // Deepest first, so a former folder nested in another is gone before its parent is checked for leftovers.
    for (const root of [...roots].sort((a, b) => b.length - a.length)) {
      if (root === destinationRoot) {
        continue;
      }
      await this.removeLeftoverFolders(root.slice(0, -suffix.length));
      this.requestedTransportRoots.delete(root);
    }
    await local.set(REQUESTED_ROOTS_KEY, [...this.requestedTransportRoots]);
    this.shared = await this.openShared();
  }

  private notifyStorageChanged(): void {
    for (const callback of this.storageChangedCallbacks) {
      callback();
    }
  }

  private async openShared(): Promise<SharedDataStore> {
    return await SharedDataStore.open({
      adapter: this.app.vault.adapter,
      folder: this.anchorFolder,
      format: 'markdown',
      isSyncEnabled: this.syncEnabled && this.blockedMovedAnchorFolder === undefined,
      kind: 'last-write-wins',
      local: ensureNonNullable(this.local),
      pluginId: PLUGIN_ID,
      storeId: STORE_ID
    });
  }

  /**
   * Reads the relocation records stored under a folder's history.
   *
   * @param folder - The folder holding the history.
   * @returns The records, with `null` for each one that has not fully arrived or is not a record.
   */
  private async readRelocationRecords(folder: string): Promise<(null | RelocationRecord)[]> {
    const transport = new DataStoreTransport({ adapter: this.app.vault.adapter, folder, pluginId: PLUGIN_ID, storeId: STORE_ID });
    const records: (null | RelocationRecord)[] = [];
    for (const path of await transport.list()) {
      if (!path.startsWith(`${transport.root}/locations-v1/`) || !path.endsWith('.json')) {
        continue;
      }
      const value = await transport.read(path);
      records.push(isRelocationRecord(value) ? value : null);
    }
    return records;
  }

  private record(operation: Except<OriginalAttachmentNameOperation, 'time'>): void {
    const paths = operation.isFolder
      ? [...this.names.keys()].filter((path) => path.startsWith(`${operation.path}/`))
      : [operation.path];
    const observed = paths.flatMap((path) => this.history.getObserved(path));
    const timed: OriginalAttachmentNameOperation = {
      ...operation,
      ...(observed.length > 0 && (operation.kind === 'remove' || operation.kind === 'rename') && { observed }),
      time: Math.max(Date.now(), this.history.time + 1)
    };

    const key = window.crypto.randomUUID();
    this.history.add(key, timed);
    this.pending.set(key, { ...timed });
  }

  /**
   * Removes what a moved store leaves behind in its former folder: the plugin's own subfolder and the folder itself,
   * each only when nothing is left in it but the plugin's `README.md` and hidden files.
   *
   * @param folder - The store's former parent folder.
   */
  private async removeLeftoverFolders(folder: string): Promise<void> {
    const adapter = this.app.vault.adapter;
    for (const path of [`${folder}/${PLUGIN_DATA_SUBFOLDER_NAME}`, folder]) {
      if (!await adapter.exists(path)) {
        continue;
      }
      const listed = await adapter.list(path);
      if (listed.folders.length > 0) {
        return;
      }
      for (const file of listed.files) {
        if (file.slice(file.lastIndexOf('/') + 1).startsWith('.')) {
          continue;
        }
        if (file !== `${path}/${PLUGIN_DATA_FOLDER_README_FILE_NAME}` || !isPluginDataFolderReadme(await adapter.read(file))) {
          return;
        }
      }
      await adapter.rmdir(path, true);
    }
  }

  /**
   * Picks the folder this device opens the store at: its permanent discovery anchor.
   *
   * The choice lives in IndexedDB and never in the synchronized settings, because a different anchor is an independent
   * store. A device that is still undecided joins an earlier version's history as soon as the vault holds it, and
   * otherwise uses the new default folder. It is fixed when synchronization is first enabled.
   *
   * @param shouldScanFileSystemForNewDevice - Whether an undecided device looks for moved history through the file
   *   system, which finds folders the vault index hides but costs a walk of the whole vault. Loading uses the index;
   *   enabling synchronization, which fixes the anchor for good, scans.
   * @returns The anchor folder.
   */
  private async resolveAnchorFolder(shouldScanFileSystemForNewDevice: boolean): Promise<string> {
    const local = ensureNonNullable(this.local);
    const adapter = this.app.vault.adapter;
    const stored = await local.get(ANCHOR_FOLDER_KEY);
    if (stored !== undefined && typeof stored !== 'string') {
      throw new Error('Invalid original-name anchor folder.');
    }
    const previousBlock = this.blockedMovedAnchorFolder;
    this.blockedMovedAnchorFolder = undefined;
    if (stored !== undefined && stored !== PENDING_ANCHOR_FOLDER) {
      if (await adapter.exists(getOriginalNameTransportRoot(stored))) {
        return stored;
      }
      /*
       * The anchor's history is gone from where this device left it. When it is in exactly one other folder, the
       * user moved it (or a folder above it), here or on another device, so follow it. Writing at the old anchor
       * would recreate it and split the history in two. The file system is scanned, because plugin data is usually
       * moved into a folder that an exclusion plugin hides from the vault index. While the history found last time
       * is still where it was, only its records are read again, so a paused device does not walk the vault on every
       * flush.
       */
      const moved = previousBlock !== undefined && await adapter.exists(getOriginalNameTransportRoot(previousBlock))
        ? { canOpen: await this.canOpenAnchor(previousBlock, await this.readRelocationRecords(previousBlock)), folder: previousBlock }
        : await this.findAnchorElsewhere(stored, true);
      if (moved === undefined) {
        return stored;
      }
      if (!moved.canOpen) {
        this.blockedMovedAnchorFolder = moved.folder;
        return stored;
      }
      this.consoleDebugComponent.consoleDebug(`Original name history moved from '${stored}' to '${moved.folder}'. Following it.`);
      await local.set(ANCHOR_FOLDER_KEY, moved.folder);
      return moved.folder;
    }
    if (await adapter.exists(getOriginalNameTransportRoot(LEGACY_PLUGIN_DATA_FOLDER))) {
      await local.set(ANCHOR_FOLDER_KEY, LEGACY_PLUGIN_DATA_FOLDER);
      return LEGACY_PLUGIN_DATA_FOLDER;
    }
    if (await adapter.exists(getOriginalNameTransportRoot(DEFAULT_PLUGIN_DATA_FOLDER))) {
      return DEFAULT_PLUGIN_DATA_FOLDER;
    }
    // A new device joins history that another device moved out of the default folders.
    const discovered = await this.findAnchorElsewhere(DEFAULT_PLUGIN_DATA_FOLDER, shouldScanFileSystemForNewDevice);
    if (discovered?.canOpen) {
      await local.set(ANCHOR_FOLDER_KEY, discovered.folder);
      return discovered.folder;
    }
    return DEFAULT_PLUGIN_DATA_FOLDER;
  }

  private showMovedAnchorBlockedNotice(): void {
    if (this.blockedMovedAnchorFolder === undefined) {
      return;
    }
    this.pluginNoticeComponent.showNotice(
      t(($) => $.originalAttachmentNames.storage.movedHistoryCannotBeFollowed, { folder: this.blockedMovedAnchorFolder, previousFolder: this.anchorFolder }),
      { mode: PluginNoticeMode.Separate }
    );
  }

  private showWarning(): void {
    const paths = [...this.unknownPaths].sort((a, b) => a.localeCompare(b));
    this.unknownPaths.clear();

    this.pluginNoticeComponent.showNotice(
      createFragment((f) => {
        appendCodeBlock(f, '{{originalAttachmentFileName}}');
        f.appendText(t(($) => $.originalAttachmentNames.unknownNotice.message, { count: paths.length }));
        f.appendText(' ');
        const detailsButton = new ButtonComponent(f.createSpan());
        detailsButton.setButtonText(t(($) => $.originalAttachmentNames.unknownNotice.details));
        detailsButton.onClick(convertAsyncToSync(async () => {
          await alert({
            app: this.app,
            message: createFragment((messageFragment) => {
              messageFragment.createEl('p', { text: t(($) => $.originalAttachmentNames.unknownDetails.explanation) });
              const listEl = messageFragment.createEl('ul');
              for (const path of paths) {
                listEl.createEl('li', { text: path });
              }
            }),
            title: t(($) => $.originalAttachmentNames.unknownDetails.title)
          });
        }));
      }),
      { mode: PluginNoticeMode.Separate }
    );
  }

  /**
   * Sends a store folder to the trash the user chose, through the vault when it indexes the folder.
   *
   * @param path - Vault-relative path.
   */
  private async trashPath(path: string): Promise<void> {
    const file = this.app.vault.getAbstractFileByPath(path);
    if (file) {
      await this.app.fileManager.trashFile(file);
      return;
    }
    const adapter = this.app.vault.adapter;
    if (!await adapter.trashSystem(path)) {
      await adapter.trashLocal(path);
    }
  }
}

/**
 * Where this plugin's history goes under a plugin data folder.
 *
 * @param folder - The vault-relative plugin data folder.
 * @returns The vault-relative history root.
 */
export function getOriginalNameTransportRoot(folder: string): string {
  return `${folder}/${PLUGIN_ID}/${STORE_ID}`;
}

/**
 * Tells whether the library can open history found at a folder other than this device's anchor.
 *
 * It can when the history has no relocation record, or when its records start at that folder. An incomplete record is
 * refused by the library until it arrives in full, so it cannot be opened yet either.
 *
 * @param folder - The folder holding the history.
 * @param records - Its relocation records, `null` for each one that has not fully arrived.
 * @returns Whether it can be opened.
 */
function isRelocationLocation(value: unknown): value is RelocationLocation {
  return typeof value === 'object' && value !== null && 'folder' in value && typeof value.folder === 'string';
}

function isRelocationRecord(value: unknown): value is RelocationRecord {
  return typeof value === 'object' && value !== null && 'from' in value && isRelocationLocation(value.from) && 'to' in value
    && isRelocationLocation(value.to) && (!('anchor' in value) || isRelocationLocation(value.anchor));
}

function isStoredOriginalAttachmentNames(value: unknown): value is StoredOriginalAttachmentNames {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const record = value as Partial<Record<keyof StoredOriginalAttachmentNames, unknown>>;
  return typeof record.version === 'number' && typeof record.names === 'object' && record.names !== null && !Array.isArray(record.names);
}

/**
 * Maps a folder a relocation record names onto the folder its anchor now lives at, as `DataStoreLocations` does.
 *
 * @param folder - The folder the record names.
 * @param formerAnchorFolder - The anchor folder the record was written at.
 * @param anchorFolder - The folder holding the anchor now.
 * @returns The folder as it is now.
 */
function remapToMovedAnchor(folder: string, formerAnchorFolder: string, anchorFolder: string): string {
  if (folder === formerAnchorFolder) {
    return anchorFolder;
  }
  if (folder.startsWith(`${formerAnchorFolder}/`)) {
    return `${anchorFolder}${folder.slice(formerAnchorFolder.length)}`;
  }
  return folder;
}
