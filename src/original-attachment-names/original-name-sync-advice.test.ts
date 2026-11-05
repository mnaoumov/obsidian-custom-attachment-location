import {
  describe,
  expect,
  it
} from 'vitest';

import { PluginSettings } from '../settings/plugin-settings.ts';
import { ObsidianSyncState } from './obsidian-sync-status.ts';
import {
  doesAnySettingReadOriginalAttachmentFileName,
  getOriginalNameSyncAdvice,
  OriginalNameSyncAdvice
} from './original-name-sync-advice.ts';

describe('getOriginalNameSyncAdvice', () => {
  it.each([
    [false, false, ObsidianSyncState.Off, true, OriginalNameSyncAdvice.ObsidianSyncNotConnected],
    [false, false, ObsidianSyncState.NotConnected, true, OriginalNameSyncAdvice.ObsidianSyncNotConnected],
    [false, false, ObsidianSyncState.NotConnected, false, OriginalNameSyncAdvice.ObsidianSyncNotConnected],
    [false, false, ObsidianSyncState.Connected, true, OriginalNameSyncAdvice.Recommended],
    [false, false, ObsidianSyncState.Connected, false, OriginalNameSyncAdvice.NotNeeded],
    [true, true, ObsidianSyncState.Connected, true, OriginalNameSyncAdvice.None],
    [true, true, ObsidianSyncState.Off, true, OriginalNameSyncAdvice.EnabledWithoutObsidianSync],
    [true, true, ObsidianSyncState.NotConnected, false, OriginalNameSyncAdvice.EnabledWithoutObsidianSync],
    [true, false, ObsidianSyncState.Off, true, OriginalNameSyncAdvice.None],
    [true, false, ObsidianSyncState.Connected, false, OriginalNameSyncAdvice.None]
  ])(
    'sync on: %s, Obsidian Sync provider: %s, Obsidian Sync: %s, template reads the name: %s -> %s',
    (isSyncEnabled, isObsidianSyncProvider, obsidianSyncState, doesTemplateReadOriginalName, expected) => {
      expect(getOriginalNameSyncAdvice({ doesTemplateReadOriginalName, isObsidianSyncProvider, isSyncEnabled, obsidianSyncState })).toBe(expected);
    }
  );
});

describe('doesAnySettingReadOriginalAttachmentFileName', () => {
  it('is false for the default settings', () => {
    expect(doesAnySettingReadOriginalAttachmentFileName(new PluginSettings())).toBe(false);
  });

  it.each(
    [
      'attachmentFolderPath',
      'collectedAttachmentFileName',
      'generatedAttachmentFileName',
      'insertedLinkText',
      'markdownUrlFormat',
      'renamedAttachmentFileName'
    ] as const
  )('finds the token in %s', (key) => {
    const settings = new PluginSettings();
    settings[key] = 'x-{{originalAttachmentFileName:lower}}';
    expect(doesAnySettingReadOriginalAttachmentFileName(settings)).toBe(true);
  });

  it('finds the token read by custom token code', () => {
    const settings = new PluginSettings();
    // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is the persisted settings key.
    settings.customTokensStr = 'exports.tokens = { name: (ctx) => ctx.originalAttachmentFileName };';
    expect(doesAnySettingReadOriginalAttachmentFileName(settings)).toBe(true);
  });
});
