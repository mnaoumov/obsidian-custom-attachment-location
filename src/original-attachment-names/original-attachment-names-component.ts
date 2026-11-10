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
  TAbstractFile
} from 'obsidian';
import type {
  Except,
  JsonValue
} from 'type-fest';

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
import {
  ensureNonNullable,
  isStringArray
} from '@mnaoumov/typescript-lib/type-guards';
import {
  ButtonComponent,
  Component,
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
  LEGACY_PLUGIN_DATA_FOLDER,
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
export class OriginalAttachmentNamesComponent extends Component {
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
      this.anchorFolder = await this.resolveAnchorFolder();
      this.shared = await this.openShared();
      this.showMovedAnchorBlockedNotice();
      await this.deleteRetiredSourcePaths(this.shared);
      this.history.merge(this.shared.entries());
      await this.migrateLegacy();
    } catch (error) {
      this.local.close();
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
    this.registerDomEvent(document, 'visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        synchronize();
      }
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
   * Copies and verifies history through the library's anchored relocation protocol.
   * Settings changes alone never move the writer; every device keeps opening the original anchor.
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
      this.requestedTransportRoots.add(`${folder}/${PLUGIN_ID}/${STORE_ID}`);
      await ensureNonNullable(this.local).set(REQUESTED_ROOTS_KEY, [...this.requestedTransportRoots]);
      await this.shared.relocate({ folder, format: 'json' });
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
          const anchorFolder = await this.resolveAnchorFolder();
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
   * by the candidates' relocation records are set aside, and exactly one candidate must remain. That one can be
   * opened when it has no relocation record, or when its records start at it. A chain that starts at another folder
   * means the anchor itself was moved after a relocation, and the library refuses to open such a chain.
   *
   * @param excludedFolder - The anchor folder whose history is gone.
   * @returns The anchor found and whether it can be opened, or `undefined` when there is none or more than one.
   */
  private async findAnchorElsewhere(excludedFolder: string): Promise<FoundAnchor | undefined> {
    const suffix = `/${PLUGIN_ID}/${STORE_ID}`;
    const candidates = this.app.vault.getAllFolders()
      .map((folder) => folder.path)
      .filter((path) => path.endsWith(suffix))
      .map((path) => path.slice(0, -suffix.length))
      .filter((folder) => folder !== excludedFolder);
    const recordsByFolder = new Map<string, (null | RelocationRecord)[]>();
    for (const folder of candidates) {
      recordsByFolder.set(folder, await this.readRelocationRecords(folder));
    }
    const destinations = new Set(
      [...recordsByFolder.values()].flat()
        .filter((record): record is RelocationRecord => record !== null && record.to.folder !== record.from.folder)
        .map((record) => record.to.folder)
    );
    const anchors = candidates.filter((folder) => !destinations.has(folder));
    if (anchors.length !== 1) {
      if (anchors.length > 1) {
        this.consoleDebugComponent.consoleDebug(`Original name history was found in several folders, so none is followed: ${anchors.join(', ')}.`);
      }
      return undefined;
    }
    const folder = ensureNonNullable(anchors[0]);
    const records = ensureNonNullable(recordsByFolder.get(folder));
    // An incomplete record is refused by the library until it arrives in full, so it cannot be opened yet either.
    return {
      canOpen: records.length === 0 || (!records.includes(null) && records.some((record) => ensureNonNullable(record).from.folder === folder)),
      folder
    };
  }

  private async flushImpl(): Promise<void> {
    let shared = this.shared;
    if (!shared) {
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
    const anchorFolder = await this.resolveAnchorFolder();
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
    // eslint-disable-next-line n/no-unsupported-features/node-builtins -- This is the renderer Web Crypto API.
    const key = window.crypto.randomUUID();
    this.history.add(key, timed);
    this.pending.set(key, { ...timed });
  }

  /**
   * Picks the folder this device opens the store at: its permanent discovery anchor.
   *
   * The choice lives in IndexedDB and never in the synchronized settings, because a different anchor is an independent
   * store. A device that is still undecided joins an earlier version's history as soon as the vault holds it, and
   * otherwise uses the new default folder. It is fixed when synchronization is first enabled.
   *
   * @returns The anchor folder.
   */
  private async resolveAnchorFolder(): Promise<string> {
    const local = ensureNonNullable(this.local);
    const adapter = this.app.vault.adapter;
    const stored = await local.get(ANCHOR_FOLDER_KEY);
    if (stored !== undefined && typeof stored !== 'string') {
      throw new Error('Invalid original-name anchor folder.');
    }
    this.blockedMovedAnchorFolder = undefined;
    if (stored !== undefined && stored !== PENDING_ANCHOR_FOLDER) {
      if (await adapter.exists(getOriginalNameTransportRoot(stored))) {
        return stored;
      }
      /*
       * The anchor's history is gone from where this device left it. When it is in exactly one other folder, the
       * user moved it (or a folder above it), here or on another device, so follow it. Writing at the old anchor
       * would recreate it and split the history in two.
       */
      const moved = await this.findAnchorElsewhere(stored);
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
    const discovered = await this.findAnchorElsewhere(DEFAULT_PLUGIN_DATA_FOLDER);
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

function isRelocationLocation(value: unknown): value is RelocationLocation {
  return typeof value === 'object' && value !== null && 'folder' in value && typeof value.folder === 'string';
}

function isRelocationRecord(value: unknown): value is RelocationRecord {
  return typeof value === 'object' && value !== null && 'from' in value && isRelocationLocation(value.from) && 'to' in value
    && isRelocationLocation(value.to);
}

function isStoredOriginalAttachmentNames(value: unknown): value is StoredOriginalAttachmentNames {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const record = value as Partial<Record<keyof StoredOriginalAttachmentNames, unknown>>;
  return typeof record.version === 'number' && typeof record.names === 'object' && record.names !== null && !Array.isArray(record.names);
}
