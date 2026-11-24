export const enGB = {
  attachmentCollector: {
    confirm: 'Do you want to collect attachments for all notes in folders recursively?\n{{folders}}\nThis operation cannot be undone.',
    progressBar: {
      message: 'Collecting attachments {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Collecting attachments...'
    }
  },
  buttons: {
    copy: 'Copy',
    move: 'Move',
    previewAttachmentFile: 'Preview attachment file',
    skip: 'Skip'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Attachment {{attachment}} is referenced by multiple notes.',
    heading: 'Collecting attachment used by multiple notes',
    noPriorityWinnerReason: {
      EmptyList: 'It was not moved because the {{settingName}} setting is empty, so nothing decides which of these notes owns it.',
      NoMatch: 'It was not moved because none of these notes matches any entry in the {{settingName}} setting.',
      Tie: 'It was not moved because several of these notes match the {{settingName}} setting equally well, so it names no single owner.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Should use the same action for other problematic attachments'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Collect attachments in current folder',
    collectAttachmentsCurrentNote: 'Collect attachments in current note',
    collectAttachmentsEntireVault: 'Collect attachments in entire vault'
  },
  links: {
    documentation: 'documentation',
    tokens: 'tokens'
  },
  menuItems: {
    collectAttachmentsInFile: 'Collect attachments in file',
    collectAttachmentsInFiles: 'Collect attachments in files'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Collecting attachments for \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Collecting attachments cancelled. See console for details.',
    generatedAttachmentFileNameIsInvalid: 'Generated attachment file name \'{{path}}\' is invalid.\n{{validationMessage}}\nCheck your {{settingName}} setting.',
    notePathIsIgnored: 'Note path is ignored'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Cancel',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Items per page:',
      jumpToPage: 'Jump to page:'
    },
    notices: {
      attachmentIsStillUsed: 'Attachment {{attachmentPath}} is still used by other notes. It will not be deleted.',
      unhandledError: 'An unhandled error occurred. Please check the console for more information.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'all files are renamed.',
        displayText: 'All'
      },
      none: {
        description: 'their names are preserved.',
        displayText: 'None'
      },
      onlyPastedImages: {
        description: 'only pasted images are renamed. Applies only when the PNG image content is pasted from the clipboard directly. Typically, for pasting screenshots.',
        displayText: 'Only pasted images'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'cancel the attachment collecting.',
        displayText: 'Cancel'
      },
      copy: {
        description: 'copy the attachment to the new location.',
        displayText: 'Copy'
      },
      move: {
        description: 'move the attachment to the new location.',
        displayText: 'Move'
      },
      prompt: {
        description: 'prompt the user to choose the action.',
        displayText: 'Prompt'
      },
      skip: {
        description: 'skip the attachment and proceed to the next one.',
        displayText: 'Skip'
      }
    },
    defaultImageSizeDimension: {
      height: 'Height',
      width: 'Width'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Custom tokens were commented out as they have to be updated to the new format introduced in plugin version 9.0.0.\n// Refer to the documentation ({{customTokensDocumentationUrl}}) for more information.',
      deprecated: 'The format of custom token registration changed. Please update your tokens accordingly. Refer to the {{documentation}} for more information.'
    },
    legacyRenameAttachmentsToLowerCase: 'The {{setting}} setting is deprecated. Use the {{format}} format instead. See the {{documentation}} for more information.',
    markdownUrlFormat: {
      deprecated: 'You have potentially incorrect value set for the {{setting}} format. Please refer to the {{documentation}} for more information. This message will not be shown again.'
    },
    specialCharacters: 'The {{setting}} default setting value was changed. Your setting value was updated to the new default value.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'The default image size must be in pixels or percentage',
      invalidCustomTokensCode: 'Invalid custom tokens code',
      invalidRegularExpression: 'Invalid regular expression {{regExp}}',
      specialCharactersMustNotContainSlash: 'Special characters must not contain /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Special character replacement must not contain invalid file name path characters.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'When attaching files:',
      name: 'Attachment rename mode'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'When the collected attachment is used by multiple notes:',
      name: 'Collect attachment used by multiple notes mode'
    },
    collectedAttachmentFileName: {
      description: 'See available {{tokens}}.\nLeave empty to keep the current attachment file name.',
      name: 'Collected attachment file name'
    },
    customTokens: {
      description: 'Custom tokens to be used.\nSee the {{documentation}} for more information.\n⚠️ Custom tokens can be an arbitrary JavaScript code. If poorly written, it can cause the data loss. Use it at your own risk.',
      name: 'Custom tokens'
    },
    defaultImageSize: {
      description: 'The default image size.\nCan be specified in pixels ({{pixels}}) or percentage of the full image size ({{percentage}}).\nLeave blank to use the original image size.',
      name: 'Default image size'
    },
    duplicateNameSeparator: {
      description: 'When you are pasting/dragging a file with the same name as an existing file, this separator will be added to the file name.\nE.g., when you are dragging file {{existingFile}}, it will be renamed to {{firstAvailableName}}, {{secondAvailableName}}, etc, getting the first name available.',
      name: 'Duplicate name separator'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Exclude attachments from the following paths when the {{command}} command is executed.\nInsert each path on a new line.\n{{pathSyntax}}\nIf the setting is empty, no paths are excluded from attachment collecting.',
      name: 'Exclude paths from attachment collecting'
    },
    generatedAttachmentFileName: {
      description: 'See available {{tokens}}.',
      name: 'Generated attachment file name'
    },
    jpegQuality: {
      description: 'The smaller the quality, the greater the compression ratio.',
      name: 'JPEG Quality'
    },
    locationForNewAttachments: {
      description: 'Start with {{relativePrefix}} for paths relative to parent folder of note.\nSee available {{tokens}}.\nDot-folders like {{dotFolder}} are not recommended, because Obsidian does not track them. You might need to use the {{unhidePlugin}} plugin to manage them.',
      name: 'Location for new attachments'
    },
    markdownUrlFormat: {
      description: 'Format for the URL that will be inserted into Markdown when an attachment is added. It is applied at that moment only: a link Obsidian rewrites later, when a note or an attachment is renamed or moved, gets the default format.\nSee available {{tokens}}.\nLeave blank to use the default format.',
      name: 'Markdown URL format'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Whether to apply the attachment folder and file name settings to attachments that OTHER plugins create.\nSome plugins write an attachment into the vault under a name of their own, without asking Obsidian where it belongs. When this is on, such a file is moved and renamed right after it appears.\nOnly files created while a note is open, and linked from a note, are touched: a file no note links to is data another plugin keeps for itself and stays where it was written. Files arriving from a sync or a vault import are never touched.\n{{modes}}\nThe creating plugin is identified from the call stack of the write. That is best-effort: no plugin is identified for a file written by Obsidian itself, by a sync client, or by a plugin that defers its write. Such a file counts as NOT being in the list below.',
      name: 'Rename attachments created by other plugins'
    },
    renameAttachmentsToLowerCase: 'Rename attachments to lower case',
    renamedAttachmentFileName: {
      description: 'See available {{tokens}}.\nLeave empty to keep the current attachment file name.',
      name: 'Renamed attachment file name'
    },
    resetToSampleCustomTokens: {
      message: 'Are you sure you want to reset the custom tokens to the sample custom tokens? Your changes will be lost.',
      title: 'Reset to sample custom tokens'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Whether to convert pasted images to JPEG. Applies only when the PNG image content is pasted from the clipboard directly. Typically, for pasting screenshots.',
      name: 'Should convert pasted images to JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'If enabled, attachments processed via the {{command}} commands will be renamed according to the {{setting}} setting.',
      name: 'Should rename collected attachments'
    },
    specialCharacters: {
      description: 'Special characters in attachment folder and file name to be replaced or removed.\nLeave blank to preserve special characters.',
      name: 'Special characters'
    },
    specialCharactersReplacement: {
      description: 'Replacement string for special characters in attachment folder and file name.\nLeave blank to remove special characters.',
      name: 'Special characters replacement'
    },
    timeoutInSeconds: {
      description: 'The timeout in seconds for all operations.\nIf {{zero}} is set, the operations execution timeout is disabled.',
      name: 'Timeout in seconds'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Rename attachment file',
    folderTitle: 'Choose attachment folder',
    previewModal: {
      title: 'Preview attachment file \'{{fullFileName}}\''
    },
    title: 'Provide a value for the prompt token'
  },
  regularExpression: '/regular expression/'
};
