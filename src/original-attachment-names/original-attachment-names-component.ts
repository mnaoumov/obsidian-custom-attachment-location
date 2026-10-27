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
 * this plugin's own renames and the user's renames inside Obsidian. It is kept in a file of its own beside
 * `data.json`, never in the settings: it grows with the vault, and a settings export has no business carrying it.
 */

import type { ConsoleDebugComponent } from '@mnaoumov/obsidian-lib/components/console-debug-component';
import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type {
  App,
  Debouncer,
  TAbstractFile
} from 'obsidian';

import { PluginNoticeMode } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import { appendCodeBlock } from '@mnaoumov/obsidian-lib/html-element';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { alert } from '@mnaoumov/obsidian-lib/modals/alert';
import {
  convertAsyncToSync,
  invokeAsyncSafely
} from '@mnaoumov/typescript-lib/async';
import {
  ButtonComponent,
  Component,
  debounce,
  TFile,
  TFolder
} from 'obsidian';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { ActionContext } from '../tokens/token-evaluator-context.ts';

import { isNonInteractiveActionContext } from '../tokens/token-evaluator-context.ts';

/**
 * The name of the file the records are kept in, inside the plugin's folder.
 */
export const ORIGINAL_ATTACHMENT_NAMES_FILE_NAME = 'original-attachment-names.json';

const STORE_FORMAT_VERSION = 1;
const SAVE_DEBOUNCE_IN_MILLISECONDS = 1000;
const WARNING_DEBOUNCE_IN_MILLISECONDS = 1000;

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

interface OriginalAttachmentNamesComponentConstructorParams {
  readonly app: App;
  readonly consoleDebugComponent: ConsoleDebugComponent;
  readonly pluginNoticeComponent: PluginNoticeComponent;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly storeFilePath: string;
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
   * How many records there are.
   *
   * @returns The count.
   */
  public get size(): number {
    return this.names.size;
  }

  private readonly app: App;
  private readonly consoleDebugComponent: ConsoleDebugComponent;
  private readonly expectedArrivals = new Map<string, ExpectedArrival>();

  private readonly names = new Map<string, string>();
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly pluginSettingsComponent: PluginSettingsComponent;
  private readonly saveDebounced: Debouncer<[], void>;
  private readonly showWarningDebounced: Debouncer<[], void>;
  private readonly storeFilePath: string;
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
        invokeAsyncSafely(() => this.save());
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
   * Forgets the given records, so their attachments fall back to their current names, with the warning.
   *
   * @param paths - The attachments' paths.
   * @returns How many records were removed.
   */
  public forget(paths: readonly string[]): number {
    let count = 0;
    for (const path of paths) {
      if (this.names.delete(path)) {
        count++;
      }
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
    const count = this.names.size;
    this.names.clear();
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
   * Reads the records from disk. Called once, before anything asks for a name.
   */
  public async loadFromDisk(): Promise<void> {
    this.names.clear();
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
      if (typeof fileName === 'string') {
        this.names.set(path, fileName);
      }
    }
  }

  public override onload(): void {
    super.onload();
    this.registerEvent(this.app.vault.on('create', this.handleCreate.bind(this)));
    this.registerEvent(this.app.vault.on('rename', this.handleRename.bind(this)));
    this.registerEvent(this.app.vault.on('delete', this.handleDelete.bind(this)));
  }

  public override onunload(): void {
    super.onunload();
    this.showWarningDebounced.cancel();
    // A record changed in the last second would otherwise be lost with the plugin.
    this.saveDebounced.run();
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
   * Records the name an attachment arrived with, replacing any earlier record for the path.
   *
   * @param path - The attachment's path.
   * @param fileName - The name, extension included.
   */
  public set(path: string, fileName: string): void {
    if (this.names.get(path) === fileName) {
      return;
    }
    this.names.set(path, fileName);
    this.saveDebounced();
  }

  private getPathsUnder(folderPath: string): string[] {
    const prefix = `${folderPath}/`;
    return [...this.names.keys()].filter((path) => path.startsWith(prefix));
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
    if (file instanceof TFolder) {
      this.forget(this.getPathsUnder(file.path));
      return;
    }

    this.forget([file.path]);
  }

  private handleRename(file: TAbstractFile, oldPath: string): void {
    // Whether the vault also reports each child of a renamed folder or not, the prefix move is idempotent: a child
    // already moved has no record left under the old prefix.
    const moves: [string, string][] = file instanceof TFolder
      ? this.getPathsUnder(oldPath).map((path) => [path, file.path + path.slice(oldPath.length)])
      : [[oldPath, file.path]];

    let isChanged = false;
    for (const [fromPath, toPath] of moves) {
      const fileName = this.names.get(fromPath);
      if (fileName === undefined) {
        continue;
      }
      this.names.delete(fromPath);
      this.names.set(toPath, fileName);
      isChanged = true;
    }

    if (isChanged) {
      this.saveDebounced();
    }
  }

  private async save(): Promise<void> {
    const stored: StoredOriginalAttachmentNames = {
      names: Object.fromEntries(this.names),
      version: STORE_FORMAT_VERSION
    };
    // Compact on purpose: the file grows with the vault, and nobody reads it by eye.
    await this.app.vault.adapter.write(this.storeFilePath, JSON.stringify(stored));
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

function isStoredOriginalAttachmentNames(value: unknown): value is StoredOriginalAttachmentNames {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  const record = value as Partial<Record<keyof StoredOriginalAttachmentNames, unknown>>;
  return typeof record.version === 'number' && typeof record.names === 'object' && record.names !== null && !Array.isArray(record.names);
}
