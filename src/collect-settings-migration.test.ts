import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import {
  beforeAll,
  describe,
  expect,
  it
} from 'vitest';

import type {
  MigratableSettingDescriptor,
  MigratableSettingValue,
  SettingsMigrationRow
} from './collect-settings-migration.ts';

import {
  applyMigrationRows,
  buildSettingsMigrationRows,
  formatMigratableSettingValue,
  formatStringListForEditing,
  getCollectModeLabel,
  getMoveModeLabel,
  MIGRATABLE_SETTING_DESCRIPTORS,
  MigratableSettingKind,
  parseStringList
} from './collect-settings-migration.ts';
import { translationsMap } from './i18n/locales/translations-map.ts';
import {
  CollectAttachmentUsedByMultipleNotesMode,
  MoveAttachmentToProperFolderUsedByMultipleNotesMode,
  PluginSettings
} from './plugin-settings.ts';

beforeAll(async () => {
  await initI18N(translationsMap);
});

function createRow(propertyName: MigratableSettingDescriptor['propertyName'], proposedValue: MigratableSettingValue): SettingsMigrationRow {
  return {
    currentValue: proposedValue,
    descriptor: getDescriptor(propertyName),
    proposedValue
  };
}

function getDescriptor(propertyName: MigratableSettingDescriptor['propertyName']): MigratableSettingDescriptor {
  const descriptor = MIGRATABLE_SETTING_DESCRIPTORS.find((candidate) => candidate.propertyName === propertyName);
  if (!descriptor) {
    throw new Error(`No descriptor for ${propertyName}`);
  }
  return descriptor;
}

describe('MIGRATABLE_SETTING_DESCRIPTORS', () => {
  it('should describe the five collect settings another plugin may propose', () => {
    expect(MIGRATABLE_SETTING_DESCRIPTORS.map((descriptor) => descriptor.propertyName)).toEqual([
      'collectAttachmentUsedByMultipleNotesMode',
      'shouldCollectAttachmentsAutomatically',
      'moveAttachmentToProperFolderUsedByMultipleNotesMode',
      'attachmentUnitFolderPaths',
      'excludePathsFromAttachmentCollecting'
    ]);
  });

  it('should name each setting the way the settings tab names it', () => {
    expect(MIGRATABLE_SETTING_DESCRIPTORS.map((descriptor) => descriptor.getName())).toEqual([
      'Collect attachment used by multiple notes mode',
      'Collect attachments automatically',
      'Move attachment to proper folder used by multiple notes mode',
      'Attachment unit folders',
      'Exclude paths from attachment collecting'
    ]);
  });
});

describe('buildSettingsMigrationRows', () => {
  it('should list only the settings the proposal names and would change', () => {
    const rows = buildSettingsMigrationRows({
      currentSettings: new PluginSettings(),
      proposedSettings: {
        attachmentUnitFolderPaths: ['Pages'],
        collectAttachmentUsedByMultipleNotesMode: 'Skip',
        excludePathsFromAttachmentCollecting: []
      }
    });

    expect(rows).toEqual([
      {
        currentValue: [],
        descriptor: getDescriptor('attachmentUnitFolderPaths'),
        proposedValue: ['Pages']
      }
    ]);
  });

  it('should keep the settings tab\'s order regardless of the proposal\'s key order', () => {
    const rows = buildSettingsMigrationRows({
      currentSettings: new PluginSettings(),
      proposedSettings: {
        excludePathsFromAttachmentCollecting: ['Archive'],
        moveAttachmentToProperFolderUsedByMultipleNotesMode: 'Skip',
        shouldCollectAttachmentsAutomatically: true
      }
    });

    expect(rows.map((row) => row.descriptor.propertyName)).toEqual([
      'shouldCollectAttachmentsAutomatically',
      'moveAttachmentToProperFolderUsedByMultipleNotesMode',
      'excludePathsFromAttachmentCollecting'
    ]);
  });
});

describe('applyMigrationRows', () => {
  it('should write every kind of value onto the settings object', () => {
    const settings = new PluginSettings();

    applyMigrationRows(settings, [
      createRow('attachmentUnitFolderPaths', ['Pages']),
      createRow('collectAttachmentUsedByMultipleNotesMode', 'Copy'),
      createRow('excludePathsFromAttachmentCollecting', ['Archive']),
      createRow('moveAttachmentToProperFolderUsedByMultipleNotesMode', 'Prompt'),
      createRow('shouldCollectAttachmentsAutomatically', true)
    ]);

    expect(settings.attachmentUnitFolderPaths).toEqual(['Pages']);
    expect(settings.collectAttachmentUsedByMultipleNotesMode).toBe(CollectAttachmentUsedByMultipleNotesMode.Copy);
    expect(settings.excludePathsFromAttachmentCollecting).toEqual(['Archive']);
    expect(settings.moveAttachmentToProperFolderUsedByMultipleNotesMode).toBe(MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt);
    expect(settings.shouldCollectAttachmentsAutomatically).toBe(true);
  });

  it('should refuse a value of the wrong type rather than corrupting the settings', () => {
    const settings = new PluginSettings();

    expect(() => {
      applyMigrationRows(settings, [createRow('shouldCollectAttachmentsAutomatically', ['yes'])]);
    }).toThrow('expects a boolean');
    expect(() => {
      applyMigrationRows(settings, [createRow('collectAttachmentUsedByMultipleNotesMode', castTo<MigratableSettingValue>('CopyAll'))]);
    }).toThrow('expects a collect mode');
    expect(() => {
      applyMigrationRows(settings, [createRow('moveAttachmentToProperFolderUsedByMultipleNotesMode', castTo<MigratableSettingValue>('Move'))]);
    }).toThrow('expects a move mode');
    expect(() => {
      applyMigrationRows(settings, [createRow('attachmentUnitFolderPaths', true)]);
    }).toThrow('expects a list of strings');
    expect(() => {
      applyMigrationRows(settings, [createRow('excludePathsFromAttachmentCollecting', castTo<MigratableSettingValue>([1]))]);
    }).toThrow('expects a list of strings');
    expect(() => {
      applyMigrationRows(settings, [createRow('excludePathsFromAttachmentCollecting', 'Skip')]);
    }).toThrow('expects a list of strings');

    expect(settings).toEqual(new PluginSettings());
  });

  it('should refuse a setting name that is not one of the migratable ones', () => {
    expect(() => {
      applyMigrationRows(new PluginSettings(), [
        {
          currentValue: true,
          descriptor: castTo<MigratableSettingDescriptor>({ propertyName: 'shouldDeleteEverything' }),
          proposedValue: true
        }
      ]);
    }).toThrow();
  });
});

describe('formatMigratableSettingValue', () => {
  it('should state a switch as enabled or disabled rather than as true or false', () => {
    expect(formatMigratableSettingValue(MigratableSettingKind.Boolean, true)).toBe('Enabled');
    expect(formatMigratableSettingValue(MigratableSettingKind.Boolean, false)).toBe('Disabled');
  });

  it('should name each mode the way its dropdown names it', () => {
    expect(formatMigratableSettingValue(MigratableSettingKind.CollectMode, 'Prompt')).toBe('Prompt');
    expect(formatMigratableSettingValue(MigratableSettingKind.MoveMode, 'CopyAll')).toBe('Copy all');
  });

  it('should state a list, and say so when it is empty', () => {
    expect(formatMigratableSettingValue(MigratableSettingKind.StringList, ['Pages', 'Drawings'])).toBe('Pages, Drawings');
    expect(formatMigratableSettingValue(MigratableSettingKind.StringList, [])).toBe('(empty)');
  });
});

describe('formatStringListForEditing', () => {
  it('should put one entry on each line', () => {
    expect(formatStringListForEditing(['Pages', 'Drawings'])).toBe('Pages\nDrawings');
  });

  it('should state a non-list value as it is, which is what a dropdown reads back', () => {
    expect(formatStringListForEditing('Skip')).toBe('Skip');
    expect(formatStringListForEditing(true)).toBe('true');
  });
});

describe('getCollectModeLabel', () => {
  it('should name every member', () => {
    const modes = [
      CollectAttachmentUsedByMultipleNotesMode.Cancel,
      CollectAttachmentUsedByMultipleNotesMode.Copy,
      CollectAttachmentUsedByMultipleNotesMode.Move,
      CollectAttachmentUsedByMultipleNotesMode.Prompt,
      CollectAttachmentUsedByMultipleNotesMode.Skip
    ];
    expect(modes.map((mode) => getCollectModeLabel(mode))).toEqual(['Cancel', 'Copy', 'Move', 'Prompt', 'Skip']);
  });

  it('should refuse a member that does not exist', () => {
    expect(() => getCollectModeLabel(castTo<CollectAttachmentUsedByMultipleNotesMode>('Unknown'))).toThrow();
  });
});

describe('getMoveModeLabel', () => {
  it('should name every member', () => {
    const modes = [
      MoveAttachmentToProperFolderUsedByMultipleNotesMode.Cancel,
      MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll,
      MoveAttachmentToProperFolderUsedByMultipleNotesMode.Prompt,
      MoveAttachmentToProperFolderUsedByMultipleNotesMode.Skip
    ];
    expect(modes.map((mode) => getMoveModeLabel(mode))).toEqual(['Cancel', 'Copy all', 'Prompt', 'Skip']);
  });

  it('should refuse a member that does not exist', () => {
    expect(() => getMoveModeLabel(castTo<MoveAttachmentToProperFolderUsedByMultipleNotesMode>('Unknown'))).toThrow();
  });
});

describe('parseStringList', () => {
  it('should trim each line and drop the blank ones', () => {
    expect(parseStringList(' Pages \n\nDrawings\n')).toEqual(['Pages', 'Drawings']);
  });
});
