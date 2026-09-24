/**
 * @file
 *
 * The comparison dialog a collect-settings migration goes through.
 *
 * Another plugin proposes the collect settings it used to hold. This dialog puts them next to what this plugin
 * holds now and lets the user approve, edit or decline them. Nothing is written until the user presses OK, and
 * a single row is declined by resetting it to the current value rather than by cancelling everything.
 */

import type { App } from 'obsidian';
import type { PromiseResolve } from 'obsidian-dev-utils/async';

import {
  ButtonComponent,
  DropdownComponent,
  ExtraButtonComponent,
  Setting,
  TextAreaComponent,
  ToggleComponent
} from 'obsidian';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  ModalBase,
  showModal
} from 'obsidian-dev-utils/obsidian/modals/modal';
import { assertNever } from 'obsidian-dev-utils/type-guards';

import type {
  MigratableSettingValue,
  SettingsMigrationRow
} from '../collect-settings-migration.ts';

import {
  formatMigratableSettingValue,
  formatStringListForEditing,
  getCollectModeLabel,
  getMoveModeLabel,
  MigratableSettingKind,
  parseStringList,
  toModeOrNull
} from '../collect-settings-migration.ts';
import {
  CollectAttachmentUsedByMultipleNotesMode,
  MoveAttachmentToProperFolderUsedByMultipleNotesMode
} from '../plugin-settings.ts';

/**
 * Parameters for {@link showCollectSettingsMigrationModal}.
 */
export interface ShowCollectSettingsMigrationModalParams {
  /**
   * An Obsidian app instance.
   */
  readonly app: App;

  /**
   * The rows to review, one per setting the proposal would actually change.
   */
  readonly rows: readonly SettingsMigrationRow[];

  /**
   * The display name of the plugin making the proposal.
   */
  readonly sourcePluginName: string;
}

interface CollectSettingsMigrationModalConstructorParams extends ShowCollectSettingsMigrationModalParams {
  readonly promiseResolve: PromiseResolve<null | SettingsMigrationRow[]>;
}

class CollectSettingsMigrationModal extends ModalBase<null | SettingsMigrationRow[]> {
  private approvedRows: null | SettingsMigrationRow[] = null;
  private readonly editedValues = new Map<string, MigratableSettingValue>();
  private readonly rows: readonly SettingsMigrationRow[];
  private readonly sourcePluginName: string;

  public constructor(params: CollectSettingsMigrationModalConstructorParams) {
    super(params);
    this.rows = params.rows;
    this.sourcePluginName = params.sourcePluginName;
  }

  public override onClose(): void {
    this.promiseResolve(this.approvedRows);
  }

  public override onOpen(): void {
    this.titleEl.setText(t(($) => $.settingsMigrationModal.title, { sourcePluginName: this.sourcePluginName }));

    this.contentEl.createEl('p', {
      text: t(($) => $.settingsMigrationModal.explanation.part1, { sourcePluginName: this.sourcePluginName })
    });
    this.contentEl.createEl('p', {
      text: t(($) => $.settingsMigrationModal.explanation.part2)
    });

    for (const row of this.rows) {
      this.renderRow(row);
    }

    const buttonsEl = this.contentEl.createDiv();

    const okButton = new ButtonComponent(buttonsEl);
    okButton.setButtonText(t(($) => $.obsidianDevUtils.buttons.ok));
    okButton.setCta();
    okButton.onClick(() => {
      this.approvedRows = this.rows.map((row) => ({
        ...row,
        proposedValue: this.editedValues.get(row.descriptor.propertyName) ?? row.proposedValue
      }));
      this.close();
    });

    const cancelButton = new ButtonComponent(buttonsEl);
    cancelButton.setButtonText(t(($) => $.obsidianDevUtils.buttons.cancel));
    cancelButton.onClick(this.close.bind(this));
  }

  /**
   * Wires a mode dropdown. Its option values are the published spellings, so a chosen value is stored as it
   * is. A value the dropdown could not have produced is ignored rather than stored.
   *
   * @param dropdownComponent - The dropdown.
   * @param row - The row it edits.
   * @returns What resets it to the current value.
   */
  private bindDropdown(dropdownComponent: DropdownComponent, row: SettingsMigrationRow): () => void {
    dropdownComponent.setValue(formatStringListForEditing(row.proposedValue));
    dropdownComponent.onChange((value) => {
      const mode = toModeOrNull(row.descriptor.kind, value);
      if (mode !== null) {
        this.editedValues.set(row.descriptor.propertyName, mode);
      }
    });
    return () => {
      dropdownComponent.setValue(formatStringListForEditing(row.currentValue));
    };
  }

  private renderRow(row: SettingsMigrationRow): void {
    const setting = new Setting(this.contentEl);
    setting.setName(row.descriptor.getName());
    setting.setDesc(t(($) => $.settingsMigrationModal.currentValue, {
      value: formatMigratableSettingValue(row.descriptor.kind, row.currentValue)
    }));

    const resetToCurrentValue = this.renderValueControl(setting, row);

    const resetButton = new ExtraButtonComponent(setting.controlEl);
    resetButton.setIcon('rotate-ccw');
    resetButton.setTooltip(t(($) => $.settingsMigrationModal.resetTooltip));
    resetButton.onClick(() => {
      this.editedValues.set(row.descriptor.propertyName, row.currentValue);
      resetToCurrentValue();
    });
  }

  private renderValueControl(setting: Setting, row: SettingsMigrationRow): () => void {
    const propertyName = row.descriptor.propertyName;

    switch (row.descriptor.kind) {
      case MigratableSettingKind.Boolean: {
        const toggleComponent = new ToggleComponent(setting.controlEl);
        toggleComponent.setValue(row.proposedValue === true);
        toggleComponent.onChange((value) => {
          this.editedValues.set(propertyName, value);
        });
        return () => {
          toggleComponent.setValue(row.currentValue === true);
        };
      }

      case MigratableSettingKind.CollectMode: {
        const dropdownComponent = new DropdownComponent(setting.controlEl);
        /* eslint-disable perfectionist/sort-objects -- Need to keep the settings tab's order. */
        dropdownComponent.addOptions({
          [CollectAttachmentUsedByMultipleNotesMode.Skip]: getCollectModeLabel(CollectAttachmentUsedByMultipleNotesMode.Skip),
          [CollectAttachmentUsedByMultipleNotesMode.Move]: getCollectModeLabel(CollectAttachmentUsedByMultipleNotesMode.Move),
          [CollectAttachmentUsedByMultipleNotesMode.Copy]: getCollectModeLabel(CollectAttachmentUsedByMultipleNotesMode.Copy),
          [CollectAttachmentUsedByMultipleNotesMode.Cancel]: getCollectModeLabel(CollectAttachmentUsedByMultipleNotesMode.Cancel),
          [CollectAttachmentUsedByMultipleNotesMode.Prompt]: getCollectModeLabel(CollectAttachmentUsedByMultipleNotesMode.Prompt)
        });
        /* eslint-enable perfectionist/sort-objects -- Need to keep the settings tab's order. */
        return this.bindDropdown(dropdownComponent, row);
      }

      case MigratableSettingKind.MoveMode: {
        const dropdownComponent = new DropdownComponent(setting.controlEl);
        /* eslint-disable perfectionist/sort-objects -- Need to keep the settings tab's order. */
        dropdownComponent.addOptions({
          [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip]: getMoveModeLabel(MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip),
          [MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll]: getMoveModeLabel(MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll),
          [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel]: getMoveModeLabel(MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel),
          [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt]: getMoveModeLabel(MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt)
        });
        /* eslint-enable perfectionist/sort-objects -- Need to keep the settings tab's order. */
        return this.bindDropdown(dropdownComponent, row);
      }

      case MigratableSettingKind.StringList: {
        const textAreaComponent = new TextAreaComponent(setting.controlEl);
        textAreaComponent.setValue(formatStringListForEditing(row.proposedValue));
        textAreaComponent.onChange((value) => {
          this.editedValues.set(propertyName, parseStringList(value));
        });
        return () => {
          textAreaComponent.setValue(formatStringListForEditing(row.currentValue));
        };
      }

      default: {
        return assertNever(row.descriptor.kind);
      }
    }
  }
}

/**
 * Shows the comparison dialog and waits for the user to settle it.
 *
 * @param params - The proposal to review.
 * @returns The rows to write, carrying whatever the user edited them to, or `null` when the user cancelled.
 */
export async function showCollectSettingsMigrationModal(params: ShowCollectSettingsMigrationModalParams): Promise<null | SettingsMigrationRow[]> {
  return await showModal<null | SettingsMigrationRow[]>((promiseResolve) =>
    new CollectSettingsMigrationModal({
      ...params,
      promiseResolve
    })
  );
}
