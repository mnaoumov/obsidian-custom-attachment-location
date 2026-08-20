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
      expect(settings.shouldSetLinkDisplayTextToAttachmentFileName).toBe(false);
      expect(settings.shouldSkipCollectingAttachmentsReferencedByRawPath).toBe(false);
      expect(settings.specialCharacters).toBe(String.raw`#^[]|*\<>:?/`);
      expect(settings.specialCharactersReplacement).toBe('-');
      expect(settings.timeoutInSeconds).toBe(5);
      expect(settings.treatAsAttachmentExtensions).toStrictEqual(['.excalidraw.md']);
      expect(settings.customTokensStr).toBe('');
      expect(settings.includePaths).toStrictEqual([]);
      expect(settings.excludePaths).toStrictEqual([]);
      expect(settings.excludePathsFromAttachmentCollecting).toStrictEqual([]);
      expect(settings.excludePathsFromMultipleNotesCheck).toStrictEqual([]);
      expect(settings.attachmentUnitFolderPaths).toStrictEqual([]);
      expect(settings.notePriorities).toStrictEqual([]);
    });
  });

  describe('customTokensStr', () => {
    it('should get and set the custom tokens string', () => {
      const settings = new PluginSettings();
      expect(settings.customTokensStr).toBe('');
      // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key; renaming it would silently drop the user's custom tokens.
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

  describe('attachmentUnitFolderPaths', () => {
    it('should get and set the attachment unit folder paths', () => {
      const settings = new PluginSettings();
      expect(settings.attachmentUnitFolderPaths).toStrictEqual([]);
      settings.attachmentUnitFolderPaths = ['assets/page_files'];
      expect(settings.attachmentUnitFolderPaths).toStrictEqual(['assets/page_files']);
    });
  });

  describe('isAttachmentUnitFolder', () => {
    it('should designate nothing while the setting is empty', () => {
      const settings = new PluginSettings();
      expect(settings.isAttachmentUnitFolder('assets/page_files')).toBe(false);
    });

    it('should match a plain entry from the vault root', () => {
      const settings = new PluginSettings();
      settings.attachmentUnitFolderPaths = ['assets/page_files'];
      expect(settings.isAttachmentUnitFolder('assets/page_files')).toBe(true);
      expect(settings.isAttachmentUnitFolder('elsewhere/assets/page_files')).toBe(false);
    });

    it('should match a folder name anywhere via a regular expression', () => {
      // This is the form the feature request asked for -- designating a folder by NAME. A plain entry
      // Is anchored at the vault root, so a name-anywhere match has to be written as a regexp.
      const settings = new PluginSettings();
      settings.attachmentUnitFolderPaths = [String.raw`/(^|\/)[^/]+_files(\/|$)/`];
      expect(settings.isAttachmentUnitFolder('assets/page_files')).toBe(true);
      expect(settings.isAttachmentUnitFolder('deeply/nested/other_files')).toBe(true);
      expect(settings.isAttachmentUnitFolder('assets/plain')).toBe(false);
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

  describe('excludePathsFromMultipleNotesCheck', () => {
    it('should get and set the exclude paths from multiple notes check', () => {
      const settings = new PluginSettings();
      expect(settings.excludePathsFromMultipleNotesCheck).toStrictEqual([]);
      settings.excludePathsFromMultipleNotesCheck = [String.raw`/\.excalidraw\.md$/`];
      expect(settings.excludePathsFromMultipleNotesCheck).toStrictEqual([String.raw`/\.excalidraw\.md$/`]);
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

  describe('getNetworkImageDownloadTimeoutInMilliseconds', () => {
    it('should convert the network image download timeout from seconds to milliseconds', () => {
      const settings = new PluginSettings();
      settings.networkImageDownloadTimeoutInSeconds = 7;
      expect(settings.getNetworkImageDownloadTimeoutInMilliseconds()).toBe(7000);
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

  describe('isExcludedFromMultipleNotesCheck', () => {
    it('should exclude notes matching the multiple-notes-check exclude paths', () => {
      const settings = new PluginSettings();
      settings.excludePathsFromMultipleNotesCheck = [String.raw`/\.excalidraw\.md$/`];
      expect(settings.isExcludedFromMultipleNotesCheck('drawings/diagram.excalidraw.md')).toBe(true);
      expect(settings.isExcludedFromMultipleNotesCheck('notes/note.md')).toBe(false);
    });
  });
});
