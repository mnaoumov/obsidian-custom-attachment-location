import {
  describe,
  expect,
  it
} from 'vitest';

import { defaultTranslations } from './default.ts';

describe('defaultTranslations', () => {
  it('should expose the button labels', () => {
    expect(defaultTranslations.buttons.copy).toBe('Copy');
    expect(defaultTranslations.buttons.copyAll).toBe('Copy all');
    expect(defaultTranslations.buttons.move).toBe('Move');
    expect(defaultTranslations.buttons.previewAttachmentFile).toBe('Preview attachment file');
    expect(defaultTranslations.buttons.select).toBe('Select');
    expect(defaultTranslations.buttons.skip).toBe('Skip');
  });

  it('should expose the modal headings', () => {
    expect(defaultTranslations.collectAttachmentUsedByMultipleNotesModal.heading).toBe('Collecting attachment used by multiple notes');
    expect(defaultTranslations.moveAttachmentToProperFolderUsedByMultipleNotesModal.heading).toBe('Collecting attachment used by multiple notes');
  });

  it('should expose the command labels', () => {
    expect(defaultTranslations.commands.moveAttachmentToProperFolder).toBe('Move attachment to proper folder');
  });

  it('should merge the obsidian-dev-utils translations', () => {
    expect(defaultTranslations.obsidianDevUtils.buttons.cancel).toBeTypeOf('string');
  });

  it('should expose the prompt-with-preview modal title', () => {
    expect(defaultTranslations.promptWithPreviewModal.title).toBe('Provide a value for the prompt token');
  });

  it('should expose the release notes for version 10.0.0', () => {
    expect(defaultTranslations.releaseNotes.versions['10.0.0'].part2).toBe('documentation');
  });
});
