import { INFINITE_TIMEOUT } from 'obsidian-dev-utils/abort-controller';
import { EmptyFolderBehavior } from 'obsidian-dev-utils/obsidian/components/rename-delete-handler-component';
import {
  describe,
  expect,
  it
} from 'vitest';

import {
  AttachmentRenameMode,
  CollectAttachmentUsedByMultipleNotesMode,
  ConvertImagesToJpegMode,
  DefaultImageSizeDimension,
  MoveAttachmentToProperFolderUsedByMultipleNotesMode,
  PluginSettings
} from './plugin-settings.ts';

describe('PluginSettings', () => {
  describe('defaults', () => {
    it('should have the expected default values', () => {
      const settings = new PluginSettings();
      expect(settings.attachmentRenameMode).toBe(AttachmentRenameMode.OnlyPastedImages);
      expect(settings.collectAttachmentUsedByMultipleNotesMode).toBe(CollectAttachmentUsedByMultipleNotesMode.Skip);
      expect(settings.convertImagesToJpegMode).toBe(ConvertImagesToJpegMode.None);
      expect(settings.defaultImageSizeDimension).toBe(DefaultImageSizeDimension.Width);
      expect(settings.emptyFolderBehavior).toBe(EmptyFolderBehavior.DeleteWithEmptyParents);
      expect(settings.moveAttachmentToProperFolderUsedByMultipleNotesMode).toBe(MoveAttachmentToProperFolderUsedByMultipleNotesMode.CopyAll);
      expect(settings.duplicateNameSeparator).toBe(' ');
      expect(settings.jpegQuality).toBe(0.8);
      expect(settings.shouldHandleRenames).toBe(true);
      expect(settings.shouldRenameAttachmentFolder).toBe(true);
      expect(settings.shouldRenameAttachmentFiles).toBe(false);
      expect(settings.specialCharacters).toBe('#^[]|*\\<>:?/');
      expect(settings.specialCharactersReplacement).toBe('-');
      expect(settings.timeoutInSeconds).toBe(5);
      expect(settings.treatAsAttachmentExtensions).toStrictEqual(['.excalidraw.md']);
      expect(settings.customTokensStr).toBe('');
      expect(settings.includePaths).toStrictEqual([]);
      expect(settings.excludePaths).toStrictEqual([]);
      expect(settings.excludePathsFromAttachmentCollecting).toStrictEqual([]);
    });
  });

  describe('customTokensStr', () => {
    it('should get and set the custom tokens string', () => {
      const settings = new PluginSettings();
      expect(settings.customTokensStr).toBe('');
      settings.customTokensStr = 'foo';
      expect(settings.customTokensStr).toBe('foo');
    });
  });

  describe('includePaths', () => {
    it('should get and set the include paths', () => {
      const settings = new PluginSettings();
      expect(settings.includePaths).toStrictEqual([]);
      settings.includePaths = ['x'];
      expect(settings.includePaths).toStrictEqual(['x']);
    });
  });

  describe('excludePaths', () => {
    it('should get and set the exclude paths', () => {
      const settings = new PluginSettings();
      expect(settings.excludePaths).toStrictEqual([]);
      settings.excludePaths = ['a', 'b'];
      expect(settings.excludePaths).toStrictEqual(['a', 'b']);
    });
  });

  describe('excludePathsFromAttachmentCollecting', () => {
    it('should get and set the exclude paths from attachment collecting', () => {
      const settings = new PluginSettings();
      expect(settings.excludePathsFromAttachmentCollecting).toStrictEqual([]);
      settings.excludePathsFromAttachmentCollecting = ['attachments'];
      expect(settings.excludePathsFromAttachmentCollecting).toStrictEqual(['attachments']);
    });
  });

  describe('specialCharactersRegExp', () => {
    it('should build a global unicode regular expression from the special characters', () => {
      const settings = new PluginSettings();
      settings.specialCharacters = 'ab';
      const regExp = settings.specialCharactersRegExp;
      expect(regExp.flags).toBe('gu');
      expect('xaby'.replace(regExp, '-')).toBe('x-y');
    });
  });

  describe('getTimeoutInMilliseconds', () => {
    it('should return the infinite timeout when the timeout is zero', () => {
      const settings = new PluginSettings();
      settings.timeoutInSeconds = 0;
      expect(settings.getTimeoutInMilliseconds()).toBe(INFINITE_TIMEOUT);
    });

    it('should convert the timeout from seconds to milliseconds', () => {
      const settings = new PluginSettings();
      settings.timeoutInSeconds = 3;
      expect(settings.getTimeoutInMilliseconds()).toBe(3000);
    });
  });

  describe('isPathIgnored', () => {
    it('should ignore paths matching the exclude paths', () => {
      const settings = new PluginSettings();
      settings.excludePaths = ['ignored'];
      expect(settings.isPathIgnored('ignored/note.md')).toBe(true);
      expect(settings.isPathIgnored('kept/note.md')).toBe(false);
    });
  });

  describe('isExcludedFromAttachmentCollecting', () => {
    it('should exclude paths matching the attachment-collecting exclude paths', () => {
      const settings = new PluginSettings();
      settings.excludePathsFromAttachmentCollecting = ['skip'];
      expect(settings.isExcludedFromAttachmentCollecting('skip/file.png')).toBe(true);
      expect(settings.isExcludedFromAttachmentCollecting('other/file.png')).toBe(false);
    });
  });
});
