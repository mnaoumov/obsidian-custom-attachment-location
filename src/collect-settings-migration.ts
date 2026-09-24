/**
 * @file
 *
 * The value half of a collect-settings migration: what another plugin may propose, how a proposal compares
 * against what this plugin already holds, and how an approved proposal is written.
 *
 * Kept apart from the dialog so the comparison is testable without a modal, and apart from the API surface so
 * the contract stays a plain description of types.
 */

import type { ReadonlyPluginSettings } from 'obsidian-dev-utils/obsidian/components/plugin-settings-component';

import { isDeepEqual } from 'obsidian-dev-utils/object-utils';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { assertNever } from 'obsidian-dev-utils/type-guards';

import type { MigratableCollectSettings } from './plugin-api.ts';
import type { PluginSettings } from './plugin-settings.ts';

import {
  CollectAttachmentUsedByMultipleNotesMode,
  MoveAttachmentToProperFolderUsedByMultipleNotesMode
} from './plugin-settings.ts';

/**
 * How a proposed value is edited in the dialog, and what it is checked against before it is written.
 */
export enum MigratableSettingKind {
  /**
   * A switch, rendered as a toggle.
   */
  Boolean = 'Boolean',

  /**
   * One of {@link CollectAttachmentUsedByMultipleNotesMode}'s members, rendered as a dropdown.
   */
  CollectMode = 'CollectMode',

  /**
   * One of {@link MoveAttachmentToProperFolderUsedByMultipleNotesMode}'s members, rendered as a dropdown.
   */
  MoveMode = 'MoveMode',

  /**
   * A list of lines, rendered as a multi-line text box with one entry per line.
   */
  StringList = 'StringList'
}

/**
 * Parameters for {@link buildSettingsMigrationRows}.
 */
export interface BuildSettingsMigrationRowsParams {
  /**
   * What this plugin holds right now.
   */
  readonly currentSettings: ReadonlyPluginSettings<PluginSettings>;

  /**
   * What the other plugin proposes.
   */
  readonly proposedSettings: MigratableCollectSettings;
}

/**
 * What the dialog needs to know about one migratable setting.
 */
export interface MigratableSettingDescriptor {
  /**
   * The setting's name, spelled exactly as the settings tab spells it, so the dialog and the tab name the
   * same thing the same way.
   */
  getName(): string;

  /**
   * How the value is edited and validated.
   */
  readonly kind: MigratableSettingKind;

  /**
   * The property this setting lives on.
   */
  readonly propertyName: MigratableSettingPropertyName;
}

/**
 * The name of a setting another plugin may propose.
 *
 * Derived from {@link MigratableCollectSettings} rather than spelled out again, so this list cannot fall out of
 * step with the one the API publishes.
 */
export type MigratableSettingPropertyName = keyof MigratableCollectSettings;

/**
 * A value any migratable setting may hold.
 */
export type MigratableSettingValue =
  | ApiCollectAttachmentUsedByMultipleNotesMode
  | ApiMoveAttachmentToProperFolderUsedByMultipleNotesMode
  | boolean
  | readonly string[];

/**
 * One line of the comparison dialog: what this plugin holds now, against what the other plugin proposes.
 */
export interface SettingsMigrationRow {
  /**
   * What this plugin holds right now.
   */
  readonly currentValue: MigratableSettingValue;

  /**
   * The setting this row is about.
   */
  readonly descriptor: MigratableSettingDescriptor;

  /**
   * What the other plugin proposes.
   */
  readonly proposedValue: MigratableSettingValue;
}

/*
 * The published spellings of the two modes, read off the published settings rather than imported under an
 * alias: `api.d.ts` names them exactly as the library enums are named.
 */
type ApiCollectAttachmentUsedByMultipleNotesMode = NonNullable<MigratableCollectSettings['collectAttachmentUsedByMultipleNotesMode']>;

type ApiMoveAttachmentToProperFolderUsedByMultipleNotesMode = NonNullable<MigratableCollectSettings['moveAttachmentToProperFolderUsedByMultipleNotesMode']>;

/**
 * Every setting another plugin may propose, in the order the settings tab lists them. The dialog reads in the
 * same order as the tab it is about to change.
 */
export const MIGRATABLE_SETTING_DESCRIPTORS: readonly MigratableSettingDescriptor[] = [
  {
    getName: () => t(($) => $.pluginSettingsTab.collectAttachmentUsedByMultipleNotesMode.name),
    kind: MigratableSettingKind.CollectMode,
    propertyName: 'collectAttachmentUsedByMultipleNotesMode'
  },
  {
    getName: () => t(($) => $.pluginSettingsTab.shouldCollectAttachmentsAutomatically.name),
    kind: MigratableSettingKind.Boolean,
    propertyName: 'shouldCollectAttachmentsAutomatically'
  },
  {
    getName: () => t(($) => $.pluginSettingsTab.moveAttachmentToProperFolderUsedByMultipleNotesMode.name),
    kind: MigratableSettingKind.MoveMode,
    propertyName: 'moveAttachmentToProperFolderUsedByMultipleNotesMode'
  },
  {
    getName: () => t(($) => $.pluginSettingsTab.attachmentUnitFolderPaths.name),
    kind: MigratableSettingKind.StringList,
    propertyName: 'attachmentUnitFolderPaths'
  },
  {
    getName: () => t(($) => $.pluginSettingsTab.excludePathsFromAttachmentCollecting.name),
    kind: MigratableSettingKind.StringList,
    propertyName: 'excludePathsFromAttachmentCollecting'
  }
];

/*
 * The library enums each published spelling in `api.d.ts` stands for.
 *
 * Keyed by the published union rather than by the enum, and that is the compile-time tether between the two:
 * `api.d.ts` is a declaration file under `skipLibCheck`, so nothing checks its inlined unions from the inside. A
 * spelling a union gains is a missing key here, and one an enum loses or renames is a member that no longer
 * exists.
 */
const COLLECT_MODE_BY_API_NAME: Record<ApiCollectAttachmentUsedByMultipleNotesMode, CollectAttachmentUsedByMultipleNotesMode> = {
  [CollectAttachmentUsedByMultipleNotesMode.Cancel]: CollectAttachmentUsedByMultipleNotesMode.Cancel,
  [CollectAttachmentUsedByMultipleNotesMode.Copy]: CollectAttachmentUsedByMultipleNotesMode.Copy,
  [CollectAttachmentUsedByMultipleNotesMode.Move]: CollectAttachmentUsedByMultipleNotesMode.Move,
  [CollectAttachmentUsedByMultipleNotesMode.Prompt]: CollectAttachmentUsedByMultipleNotesMode.Prompt,
  [CollectAttachmentUsedByMultipleNotesMode.Skip]: CollectAttachmentUsedByMultipleNotesMode.Skip
};

const MOVE_MODE_BY_API_NAME: Record<ApiMoveAttachmentToProperFolderUsedByMultipleNotesMode, MoveAttachmentToProperFolderUsedByMultipleNotesMode> = {
  [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel]: MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel,
  [MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll]: MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll,
  [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt]: MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt,
  [MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip]: MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip
};

interface WriteMigratableSettingParams {
  readonly propertyName: MigratableSettingPropertyName;
  readonly settings: PluginSettings;
  readonly value: MigratableSettingValue;
}

/**
 * Writes the rows the user approved in the dialog, carrying whatever they edited the proposed values to.
 *
 * A value whose type does not match the setting throws rather than being written. The proposal crossed a
 * plugin boundary, so it is checked here rather than trusted.
 *
 * @param settings - The settings to write onto.
 * @param rows - The approved rows.
 */
export function applyMigrationRows(settings: PluginSettings, rows: readonly SettingsMigrationRow[]): void {
  for (const row of rows) {
    writeMigratableSetting({
      propertyName: row.descriptor.propertyName,
      settings,
      value: row.proposedValue
    });
  }
}

/**
 * Compares a proposal against what this plugin holds, and returns one row per setting that would actually
 * change. A proposal that matches the current value is not a change and is left out.
 *
 * @param params - The current settings and the proposal.
 * @returns The rows, in the settings tab's order.
 */
export function buildSettingsMigrationRows(params: BuildSettingsMigrationRowsParams): SettingsMigrationRow[] {
  const rows: SettingsMigrationRow[] = [];

  for (const descriptor of MIGRATABLE_SETTING_DESCRIPTORS) {
    const proposedValue = params.proposedSettings[descriptor.propertyName];
    if (proposedValue === undefined) {
      continue;
    }

    const currentValue = params.currentSettings[descriptor.propertyName];
    if (isDeepEqual(currentValue, proposedValue)) {
      continue;
    }

    rows.push({
      currentValue,
      descriptor,
      proposedValue
    });
  }

  return rows;
}

/**
 * Renders a value the way the comparison dialog states it.
 *
 * @param kind - How the setting is edited, which says how to read the value.
 * @param value - The value to render.
 * @returns The text to show.
 */
export function formatMigratableSettingValue(kind: MigratableSettingKind, value: MigratableSettingValue): string {
  if (typeof value === 'boolean') {
    return t(($) => value ? $.settingsMigrationModal.enabled : $.settingsMigrationModal.disabled);
  }

  if (typeof value === 'string') {
    return kind === MigratableSettingKind.MoveMode
      ? getMoveModeLabel(ensureMoveMode('moveAttachmentToProperFolderUsedByMultipleNotesMode', value))
      : getCollectModeLabel(ensureCollectMode('collectAttachmentUsedByMultipleNotesMode', value));
  }

  return value.length === 0 ? t(($) => $.settingsMigrationModal.emptyList) : value.join(', ');
}

/**
 * Renders a list value for the multi-line text box that edits it, one entry per line.
 *
 * @param value - The value to render.
 * @returns The text to edit.
 */
export function formatStringListForEditing(value: MigratableSettingValue): string {
  return typeof value === 'boolean' || typeof value === 'string' ? String(value) : value.join('\n');
}

/**
 * Names a collect mode the way the settings tab's dropdown names it.
 *
 * @param mode - The mode.
 * @returns The label.
 */
export function getCollectModeLabel(mode: CollectAttachmentUsedByMultipleNotesMode): string {
  switch (mode) {
    case CollectAttachmentUsedByMultipleNotesMode.Cancel: {
      return t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.cancel.displayText);
    }
    case CollectAttachmentUsedByMultipleNotesMode.Copy: {
      return t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.copy.displayText);
    }
    case CollectAttachmentUsedByMultipleNotesMode.Move: {
      return t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.move.displayText);
    }
    case CollectAttachmentUsedByMultipleNotesMode.Prompt: {
      return t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.prompt.displayText);
    }
    case CollectAttachmentUsedByMultipleNotesMode.Skip: {
      return t(($) => $.pluginSettings.collectAttachmentUsedByMultipleNotesMode.skip.displayText);
    }
    default: {
      return assertNever(mode);
    }
  }
}

/**
 * Names a move mode the way the settings tab's dropdown names it.
 *
 * @param mode - The mode.
 * @returns The label.
 */
export function getMoveModeLabel(mode: MoveAttachmentToProperFolderUsedByMultipleNotesMode): string {
  switch (mode) {
    case MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel: {
      return t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.cancel.displayText);
    }
    case MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll: {
      return t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.copyAll.displayText);
    }
    case MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt: {
      return t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.prompt.displayText);
    }
    case MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip: {
      return t(($) => $.pluginSettings.moveAttachmentToProperFolderUsedByMultipleNotesMode.skip.displayText);
    }
    default: {
      return assertNever(mode);
    }
  }
}

/**
 * Reads a multi-line text box back into a list. Blank lines are dropped and every entry is trimmed, so a
 * trailing newline does not become an empty entry.
 *
 * @param text - The text the user left in the box.
 * @returns The list.
 */
export function parseStringList(text: string): string[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '');
}

/**
 * Narrows a dropdown's value to a mode of the kind the dropdown edits.
 *
 * @param kind - Which mode the dropdown edits.
 * @param value - The value it reported.
 * @returns The mode, or `null` when the string names none.
 */
export function toModeOrNull(kind: MigratableSettingKind, value: string): MigratableSettingValue | null {
  if (kind === MigratableSettingKind.MoveMode) {
    return isApiMoveMode(value) ? value : null;
  }

  return isApiCollectMode(value) ? value : null;
}

function checkBoolean(propertyName: MigratableSettingPropertyName, value: MigratableSettingValue): boolean {
  if (typeof value !== 'boolean') {
    throw new TypeError(`Setting "${propertyName}" expects a boolean, got ${JSON.stringify(value)}`);
  }

  return value;
}

function ensureCollectMode(propertyName: MigratableSettingPropertyName, value: MigratableSettingValue): CollectAttachmentUsedByMultipleNotesMode {
  if (!isApiCollectMode(value)) {
    throw new TypeError(`Setting "${propertyName}" expects a collect mode, got ${JSON.stringify(value)}`);
  }

  return COLLECT_MODE_BY_API_NAME[value];
}

function ensureMoveMode(propertyName: MigratableSettingPropertyName, value: MigratableSettingValue): MoveAttachmentToProperFolderUsedByMultipleNotesMode {
  if (!isApiMoveMode(value)) {
    throw new TypeError(`Setting "${propertyName}" expects a move mode, got ${JSON.stringify(value)}`);
  }

  return MOVE_MODE_BY_API_NAME[value];
}

function ensureStringList(propertyName: MigratableSettingPropertyName, value: MigratableSettingValue): string[] {
  if (typeof value === 'boolean' || typeof value === 'string' || value.some((entry) => typeof entry !== 'string')) {
    throw new TypeError(`Setting "${propertyName}" expects a list of strings, got ${JSON.stringify(value)}`);
  }

  return [...value];
}

function isApiCollectMode(value: unknown): value is ApiCollectAttachmentUsedByMultipleNotesMode {
  return typeof value === 'string' && Object.hasOwn(COLLECT_MODE_BY_API_NAME, value);
}

function isApiMoveMode(value: unknown): value is ApiMoveAttachmentToProperFolderUsedByMultipleNotesMode {
  return typeof value === 'string' && Object.hasOwn(MOVE_MODE_BY_API_NAME, value);
}

function writeMigratableSetting(params: WriteMigratableSettingParams): void {
  const {
    propertyName,
    settings,
    value
  } = params;

  switch (propertyName) {
    case 'attachmentUnitFolderPaths': {
      settings.attachmentUnitFolderPaths = ensureStringList(propertyName, value);
      break;
    }
    case 'collectAttachmentUsedByMultipleNotesMode': {
      settings.collectAttachmentUsedByMultipleNotesMode = ensureCollectMode(propertyName, value);
      break;
    }
    case 'excludePathsFromAttachmentCollecting': {
      settings.excludePathsFromAttachmentCollecting = ensureStringList(propertyName, value);
      break;
    }
    case 'moveAttachmentToProperFolderUsedByMultipleNotesMode': {
      settings.moveAttachmentToProperFolderUsedByMultipleNotesMode = ensureMoveMode(propertyName, value);
      break;
    }
    case 'shouldCollectAttachmentsAutomatically': {
      settings.shouldCollectAttachmentsAutomatically = checkBoolean(propertyName, value);
      break;
    }
    default: {
      assertNever(propertyName);
    }
  }
}
