/**
 * @file
 *
 * The list behind `Show original attachment names`: every remembered arrival name, with the means to correct one.
 *
 * Correcting is the point. A pasted screenshot arrives as `Pasted image <timestamp>.png`, which is true but useless,
 * and a user who renames it wants the new name to be the one templates build on. `Forget all` is far too blunt for
 * that, so each row can be edited, forgotten, or reset to the file's current name.
 */

import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { PromiseResolve } from '@mnaoumov/typescript-lib/async';
import type { App } from 'obsidian';

import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import {
  ModalBase,
  showModal
} from '@mnaoumov/obsidian-lib/modals/modal';
import { convertAsyncToSync } from '@mnaoumov/typescript-lib/async';
import {
  ButtonComponent,
  ExtraButtonComponent,
  TextComponent,
  ToggleComponent
} from 'obsidian';

import type { TokenValidator } from '../tokens/token-validator.ts';
import type {
  OriginalAttachmentNameRecord,
  OriginalAttachmentNamesComponent
} from './original-attachment-names-component.ts';

import { TokenValidationMode } from '../tokens/token-validator.ts';

/**
 * Parameters for {@link showOriginalAttachmentNamesModal}.
 */
export interface ShowOriginalAttachmentNamesModalParams {
  /**
   * An Obsidian app instance.
   */
  readonly app: App;

  /**
   * The store to show and edit.
   */
  readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;

  /**
   * The component that shows the plugin's notices.
   */
  readonly pluginNoticeComponent: PluginNoticeComponent;

  /**
   * The validator an edited name must pass.
   */
  readonly tokenValidator: TokenValidator;
}

interface OriginalAttachmentNamesModalConstructorParams extends ShowOriginalAttachmentNamesModalParams {
  readonly promiseResolve: PromiseResolve<undefined>;
}

class OriginalAttachmentNamesModal extends ModalBase<undefined> {
  private editingPath: null | string = null;
  private filter = '';
  private readonly listEl = createDiv('original-attachment-names-list');
  private readonly originalAttachmentNamesComponent: OriginalAttachmentNamesComponent;
  private readonly pluginNoticeComponent: PluginNoticeComponent;
  private readonly selectedPaths = new Set<string>();
  private readonly tokenValidator: TokenValidator;
  private readonly totalsEl = createEl('p');

  public constructor(params: OriginalAttachmentNamesModalConstructorParams) {
    super(params);
    this.originalAttachmentNamesComponent = params.originalAttachmentNamesComponent;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    this.tokenValidator = params.tokenValidator;
    this.addCssClasses('original-attachment-names-modal');
  }

  public override onClose(): void {
    this.promiseResolve(undefined);
  }

  public override onOpen(): void {
    this.titleEl.setText(t(($) => $.originalAttachmentNames.showModal.title));
    this.contentEl.append(this.totalsEl);

    const toolbarEl = this.contentEl.createDiv('original-attachment-names-toolbar');
    const filterComponent = new TextComponent(toolbarEl);
    filterComponent.setPlaceholder(t(($) => $.originalAttachmentNames.showModal.filterPlaceholder));
    filterComponent.onChange((value) => {
      this.filter = value;
      this.render();
    });

    new ButtonComponent(toolbarEl)
      .setButtonText(t(($) => $.originalAttachmentNames.showModal.copyAsCsv))
      .onClick(convertAsyncToSync(async () => {
        const records = this.getShownRecords();
        await this.contentEl.win.navigator.clipboard.writeText(formatOriginalAttachmentNamesAsCsv(records));
        this.pluginNoticeComponent.showNotice(t(($) => $.originalAttachmentNames.showModal.copiedNotice, { count: records.length }));
      }));

    new ButtonComponent(toolbarEl)
      .setButtonText(t(($) => $.originalAttachmentNames.showModal.forgetSelected))
      .onClick(() => {
        this.originalAttachmentNamesComponent.forget([...this.selectedPaths]);
        this.selectedPaths.clear();
        this.render();
      });

    new ButtonComponent(toolbarEl)
      .setButtonText(t(($) => $.originalAttachmentNames.showModal.useCurrentNameForSelected))
      .onClick(() => {
        useCurrentNamesAsOriginals(this.originalAttachmentNamesComponent, this.app, [...this.selectedPaths]);
        this.selectedPaths.clear();
        this.render();
      });

    this.contentEl.append(this.listEl);
    this.render();
  }

  private getShownRecords(): OriginalAttachmentNameRecord[] {
    return this.originalAttachmentNamesComponent.getRecords().filter((record) => isOriginalAttachmentNameRecordMatch(record, this.filter));
  }

  private render(): void {
    const records = this.originalAttachmentNamesComponent.getRecords();
    const existingPaths = new Set(records.map((record) => record.path));
    for (const path of this.selectedPaths) {
      if (!existingPaths.has(path)) {
        this.selectedPaths.delete(path);
      }
    }

    this.totalsEl.setText(t(($) => $.originalAttachmentNames.showModal.totals, {
      count: records.length,
      missingCount: records.filter((record) => record.isMissing).length
    }));

    this.listEl.empty();
    if (records.length === 0) {
      this.listEl.createEl('p', { text: t(($) => $.originalAttachmentNames.showModal.empty) });
      return;
    }

    const shownRecords = records.filter((record) => isOriginalAttachmentNameRecordMatch(record, this.filter));
    if (shownRecords.length === 0) {
      this.listEl.createEl('p', { text: t(($) => $.originalAttachmentNames.showModal.noMatches) });
      return;
    }

    for (const record of shownRecords) {
      this.renderRecord(record);
    }
  }

  private renderEditor(rowEl: HTMLElement, record: OriginalAttachmentNameRecord): void {
    const editorEl = rowEl.createDiv('original-attachment-names-editor');
    const textComponent = new TextComponent(editorEl);
    textComponent.setValue(record.originalFileName);
    const errorEl = editorEl.createDiv('original-attachment-names-error');

    const save = convertAsyncToSync(async () => {
      const fileName = textComponent.getValue().trim();
      const validationMessage = await this.tokenValidator.validateFileName({
        areSingleDotsAllowed: false,
        fileName,
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Error
      });
      if (validationMessage) {
        errorEl.setText(validationMessage);
        return;
      }
      this.originalAttachmentNamesComponent.set(record.path, fileName);
      this.editingPath = null;
      this.render();
    });

    textComponent.inputEl.addEventListener('keydown', (event_) => {
      if (event_.key !== 'Enter') {
        return;
      }

      event_.preventDefault();
      save();
    });

    new ButtonComponent(editorEl)
      .setButtonText(t(($) => $.originalAttachmentNames.showModal.save))
      .setCta()
      .onClick(save);
    new ButtonComponent(editorEl)
      .setButtonText(t(($) => $.obsidianLib.buttons.cancel))
      .onClick(() => {
        this.editingPath = null;
        this.render();
      });

    textComponent.inputEl.focus();
  }

  private renderRecord(record: OriginalAttachmentNameRecord): void {
    const rowEl = this.listEl.createDiv('original-attachment-names-row');

    new ToggleComponent(rowEl)
      .setValue(this.selectedPaths.has(record.path))
      .onChange((isSelected) => {
        if (isSelected) {
          this.selectedPaths.add(record.path);
        } else {
          this.selectedPaths.delete(record.path);
        }
      });

    const textEl = rowEl.createDiv('original-attachment-names-text');
    textEl.createSpan({ cls: 'original-attachment-names-path', text: record.path });
    textEl.createSpan({ text: ' → ' });

    if (this.editingPath === record.path) {
      this.renderEditor(textEl, record);
    } else {
      textEl.createSpan({ cls: 'original-attachment-names-name', text: record.originalFileName });
    }

    if (record.isMissing) {
      textEl.createSpan({
        attr: { 'aria-label': t(($) => $.originalAttachmentNames.showModal.missingTooltip) },
        cls: 'original-attachment-names-missing',
        text: t(($) => $.originalAttachmentNames.showModal.missingBadge)
      });
    }

    const actionsEl = rowEl.createDiv('original-attachment-names-actions');
    new ExtraButtonComponent(actionsEl)
      .setIcon('pencil')
      .setTooltip(t(($) => $.originalAttachmentNames.showModal.edit))
      .onClick(() => {
        this.editingPath = record.path;
        this.render();
      });

    const useCurrentNameButton = new ExtraButtonComponent(actionsEl)
      .setIcon('rotate-ccw')
      .setTooltip(t(($) => $.originalAttachmentNames.showModal.useCurrentName))
      .onClick(() => {
        useCurrentNamesAsOriginals(this.originalAttachmentNamesComponent, this.app, [record.path]);
        this.render();
      });
    useCurrentNameButton.setDisabled(record.isMissing);

    new ExtraButtonComponent(actionsEl)
      .setIcon('trash')
      .setTooltip(t(($) => $.originalAttachmentNames.showModal.forget))
      .onClick(() => {
        this.originalAttachmentNamesComponent.forget([record.path]);
        this.render();
      });
  }
}

/**
 * Renders the records as CSV, one per line, under a `path,originalName` header.
 *
 * @param records - The records.
 * @returns The CSV text.
 */
export function formatOriginalAttachmentNamesAsCsv(records: readonly OriginalAttachmentNameRecord[]): string {
  const lines = ['path,originalName', ...records.map((record) => `${escapeCsvField(record.path)},${escapeCsvField(record.originalFileName)}`)];
  return `${lines.join('\n')}\n`;
}

/**
 * Whether a record matches the filter text, by path or by original name, ignoring case.
 *
 * @param record - The record.
 * @param filter - The filter text.
 * @returns Whether it matches.
 */
export function isOriginalAttachmentNameRecordMatch(record: OriginalAttachmentNameRecord, filter: string): boolean {
  const needle = filter.trim().toLowerCase();
  return needle === '' || record.path.toLowerCase().includes(needle) || record.originalFileName.toLowerCase().includes(needle);
}

/**
 * Shows every remembered original attachment name.
 *
 * @param params - The store and the app.
 * @returns A promise that settles when the modal closes.
 */
export async function showOriginalAttachmentNamesModal(params: ShowOriginalAttachmentNamesModalParams): Promise<void> {
  await showModal<undefined>((promiseResolve) =>
    new OriginalAttachmentNamesModal({
      ...params,
      promiseResolve
    })
  );
}

/**
 * Sets the original name of each record to its file's current name. A record whose file is missing has no current
 * name and is left alone.
 *
 * @param originalAttachmentNamesComponent - The store.
 * @param app - The Obsidian app instance.
 * @param paths - The records' paths.
 * @returns How many records changed.
 */
export function useCurrentNamesAsOriginals(originalAttachmentNamesComponent: OriginalAttachmentNamesComponent, app: App, paths: readonly string[]): number {
  let count = 0;
  for (const path of paths) {
    const file = app.vault.getFileByPath(path);
    if (!file) {
      continue;
    }
    originalAttachmentNamesComponent.set(path, file.name);
    count++;
  }
  return count;
}

function escapeCsvField(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}
