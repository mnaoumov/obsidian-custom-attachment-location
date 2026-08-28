import type { DefaultTranslationsBase } from 'obsidian-dev-utils/obsidian/i18n/default-translations';

import { en as obsidianDevUtilsEn } from 'obsidian-dev-utils/obsidian/i18n/locales/en';

export const defaultTranslations = {
  ...obsidianDevUtilsEn,
  attachmentCollector: {
    confirm: {
      part1: 'Do you want to collect attachments for all notes in folders recursively?',
      part2: 'This operation cannot be undone.'
    },
    progressBar: {
      message: 'Collecting attachments {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Collecting attachments...'
    }
  },
  buttons: {
    copy: 'Copy',
    copyAll: 'Copy all',
    move: 'Move',
    previewAttachmentFile: 'Preview attachment file',
    select: 'Select',
    skip: 'Skip'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: {
      part1: 'Attachment',
      part2: 'is referenced by multiple notes.'
    },
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
    collectAttachmentsEntireVault: 'Collect attachments in entire vault',
    deleteUnusedAttachmentsCurrentNote: 'Delete unused attachments in current note',
    deleteUnusedAttachmentsEntireVault: 'Delete unused attachments in entire vault',
    moveAttachmentToProperFolder: 'Move attachment to proper folder'
  },
  deleteUnusedAttachments: {
    confirm: {
      andMore: '... and {{count}} more.',
      count: '{{count}} attachment(s) will be moved to the trash.',
      part1: 'The following unused attachments will be moved to the trash:',
      part2: 'This operation cannot be undone.'
    },
    progressBar: {
      message: 'Scanning for unused attachments {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Scanning for unused attachments...'
    }
  },
  menuItems: {
    collectAttachmentsInFile: 'Collect attachments in file',
    collectAttachmentsInFiles: 'Collect attachments in files',
    deleteUnusedAttachmentsInFile: 'Delete unused attachments in file',
    deleteUnusedAttachmentsInFiles: 'Delete unused attachments in files'
  },
  moveAttachmentToProperFolder: {
    progressBar: {
      message: 'Moving attachment to proper folder {{iterationString}} - \'{{attachmentFilePath}}\'.',
      title: 'Moving attachment to proper folder...'
    },
    unusedAttachment: 'Attachment {{attachmentPath}} is not used by any note. It will not be moved.'
  },
  moveAttachmentToProperFolderUsedByMultipleNotesModal: {
    content: {
      part1: 'Attachment',
      part2: 'is referenced by multiple notes.',
      part3: 'Select notes to copy the attachment to.'
    },
    heading: 'Collecting attachment used by multiple notes',
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Should use the same action for other problematic attachments'
  },
  notice: {
    attachmentReferencedByRawPath: 'Skipping collecting attachment \'{{attachmentPath}}\' because it is referenced by a raw path in \'{{noteFilePath}}\'.',
    attachmentUnitFolderUsedByMultipleNotes: 'Skipping collecting attachment \'{{attachmentPath}}\' because its attachment unit folder \'{{unitFolderPath}}\' is referenced by multiple notes.',
    collectingAttachments: 'Collecting attachments for \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Collecting attachments cancelled. See console for details.',
    couldNotResolveTemplatePath: 'Could not resolve template path \'{{template}}\'. See console for details.',
    generatedAttachmentFileNameIsInvalid: {
      part1: 'Generated attachment file name \'{{path}}\' is invalid.\n{{validationMessage}}\nCheck your',
      part2: 'setting.'
    },
    notePathIsIgnored: 'Note path is ignored',
    noUnusedAttachments: 'No unused attachments found.',
    updatingLinks: 'Updating links: {{processed}}/{{total}} - \'{{currentPath}}\''
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
    convertImagesToJpegMode: {
      allImages: {
        description: 'all images are converted to JPEG.',
        displayText: 'All images'
      },
      allImagesExceptAlreadyJpeg: {
        description: 'all images except already JPEG files are converted to JPEG.',
        displayText: 'All images except already JPEG'
      },
      none: {
        description: 'do not convert images to JPEG.',
        displayText: 'None'
      },
      onlyPastedClipboardPngImages: {
        description: 'only convert pasted clipboard PNG images to JPEG.',
        displayText: 'Only pasted clipboard PNG images'
      }
    },
    defaultImageSizeDimension: {
      height: 'Height',
      width: 'Width'
    },
    emptyFolderBehavior: {
      delete: {
        description: 'will delete the empty folder.',
        displayText: 'Delete'
      },
      deleteWithEmptyParents: {
        description: 'will delete the empty folder and its empty parent folders.',
        displayText: 'Delete with empty parents'
      },
      keep: {
        description: 'will keep the empty folder.',
        displayText: 'Keep'
      }
    },
    moveAttachmentToProperFolderUsedByMultipleNotesMode: {
      cancel: {
        description: 'cancel the attachment collecting.',
        displayText: 'Cancel'
      },
      copyAll: {
        description: 'copy the attachment to the new location for all notes.',
        displayText: 'Copy all'
      },
      prompt: {
        description: 'prompt the user to choose the action.',
        displayText: 'Prompt'
      },
      skip: {
        description: 'skip the attachment and proceed to the next one.',
        displayText: 'Skip'
      }
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Custom tokens were commented out as they have to be updated to the new format introduced in plugin version 9.0.0.\n// Refer to the documentation (https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#custom-tokens) for more information.',
      deprecated: {
        part1: 'The format of custom token registration changed. Please update your tokens accordingly. Refer to the',
        part2: 'documentation',
        part3: 'for more information'
      }
    },
    legacyRenameAttachmentsToLowerCase: {
      part1: 'The',
      part2: 'setting is deprecated. Use',
      part3: 'format instead. See',
      part4: 'documentation',
      part5: 'for more information'
    },
    markdownUrlFormat: {
      deprecated: {
        part1: 'You have potentially incorrect value set for the',
        part2: 'format. Please refer to the',
        part3: 'documentation',
        part4: 'for more information',
        part5: 'This message will not be shown again.'
      }
    },
    specialCharacters: {
      part1: 'The',
      part2: 'default setting value was changed. Your setting value was updated to the new default value.'
    },
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Default image size must be in pixels or percentage',
      invalidCustomTokensCode: 'Invalid custom tokens code',
      invalidRegularExpression: 'Invalid regular expression {{regExp}}',
      specialCharactersMustNotContainSlash: 'Special characters must not contain /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Special character replacement must not contain invalid file name path characters.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: {
        part1: 'When attaching files:'
      },
      name: 'Attachment rename mode'
    },
    attachmentUnitFolderPaths: {
      description: {
        part1: 'Treat the following folders as a single attachment. When',
        part2: 'Collect attachments',
        part3: 'moves an attachment from one of them, the whole folder moves along with it.',
        part4: 'Use this for attachments that are really a folder: a saved page next to its files folder, a drawing next to the images it references.',
        part5: 'Insert each path on a new line.',
        part6: 'You can use path string or',
        part7: 'A plain path is matched from the vault root. To match a folder name wherever it appears, use a regular expression.',
        part8: 'If the setting is empty, every attachment is moved on its own, which is the behavior without this setting.'
      },
      name: 'Attachment unit folders'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: {
        part1: 'When the collected attachment is used by multiple notes:'
      },
      name: 'Collect attachment used by multiple notes mode'
    },
    collectedAttachmentFileName: {
      description: {
        part1: 'See available',
        part2: 'tokens',
        part3: 'Leave empty to keep the original attachment file name.'
      },
      name: 'Collected attachment file name'
    },
    convertImagesToJpegMode: {
      description: {
        part1: 'Which images to convert to JPEG:'
      },
      name: 'Convert images to JPEG mode'
    },
    customTokens: {
      description: {
        part1: 'Custom tokens to be used.',
        part2: 'See',
        part3: 'documentation',
        part4: 'for more information.',
        part5: '⚠️ Custom tokens can be an arbitrary JavaScript code. If poorly written, it can cause the data loss. Use it at your own risk.'
      },
      name: 'Custom tokens'
    },
    defaultImageSize: {
      description: {
        part1: 'The default image size.',
        part2: 'Can be specified in pixels',
        part3: 'or percentage of the full image size',
        part4: 'Leave blank to use the original image size.'
      },
      name: 'Default image size'
    },
    downloadNetworkImages: {
      description: 'When collecting attachments, automatically download network images referenced in markdown and save them locally.',
      name: 'Download network images'
    },
    duplicateNameSeparator: {
      description: {
        part1: 'When you are pasting/dragging a file with the same name as an existing file, this separator will be added to the file name.',
        part2: 'E.g., when you are dragging file',
        part3: ', it will be renamed to ',
        part4: ', etc, getting the first name available.'
      },
      name: 'Duplicate name separator'
    },
    emptyFolderBehavior: {
      description: {
        part1: 'When the folder becomes empty:'
      },
      name: 'Empty folder behavior'
    },
    excludePaths: {
      description: {
        part1: 'Exclude notes from the following paths.',
        part2: 'Insert each path on a new line.',
        part3: 'You can use path string or',
        part4: 'If the setting is empty, no notes are excluded.'
      },
      name: 'Exclude paths'
    },
    excludePathsFromAttachmentCollecting: {
      description: {
        part1: 'Exclude attachments from the following paths when',
        part2: 'Collect attachments',
        part3: 'command is executed.',
        part4: 'Insert each path on a new line.',
        part5: 'You can use path string or',
        part6: 'If the setting is empty, no paths are excluded from attachment collecting.'
      },
      name: 'Exclude paths from attachment collecting'
    },
    excludePathsFromMultipleNotesCheck: {
      description: {
        part1: 'Ignore notes from the following paths when checking whether an attachment is used by multiple notes during the',
        part2: 'Collect attachments',
        part3: 'and',
        part4: 'Move attachment to proper folder',
        part5: 'commands.',
        part6: 'Insert each path on a new line.',
        part7: 'You can use path string or',
        part8: 'If the setting is empty, no notes are ignored.'
      },
      name: 'Exclude paths from multiple notes check'
    },
    generatedAttachmentFileName: {
      description: {
        part1: 'See available',
        part2: 'tokens'
      },
      name: 'Generated attachment file name'
    },
    groups: {
      advanced: 'Advanced',
      collectedAttachments: 'Collected attachments',
      core: 'Core',
      customTokens: 'Custom tokens',
      deletion: 'Deletion',
      images: 'Images',
      moveRenames: 'Move/renames',
      path: 'Path',
      specialCharacters: 'Special characters'
    },
    includePaths: {
      description: {
        part1: 'Include notes from the following paths.',
        part2: 'Insert each path on a new line.',
        part3: 'You can use path string or',
        part4: 'If the setting is empty, all notes are included.'
      },
      name: 'Include paths'
    },
    jpegQuality: {
      description: 'The smaller the quality, the greater the compression ratio.',
      name: 'JPEG Quality'
    },
    locationForNewAttachments: {
      description: {
        part1: 'Start with',
        part2: 'for paths relative to parent folder of note.',
        part3: 'See available',
        part4: 'tokens',
        part5: 'Dot-folders like',
        part6: 'are not recommended, because Obsidian does not track them. You might need to use',
        part7: 'Plugin to manage them.'
      },
      name: 'Location for new attachments'
    },
    markdownUrlFormat: {
      description: {
        part1: 'Format for the URL that will be inserted into Markdown.',
        part2: 'See available',
        part3: 'tokens',
        part4: 'Leave blank to use the default format.'
      },
      name: 'Markdown URL format'
    },
    moveAttachmentToProperFolderUsedByMultipleNotesMode: {
      description: {
        part1: 'When the attachment is used by multiple notes:'
      },
      name: 'Move attachment to proper folder used by multiple notes mode'
    },
    networkImageDownloadTimeoutInSeconds: {
      description: 'The timeout in seconds for downloading each network image.',
      name: 'Network image download timeout in seconds'
    },
    notePriorities: {
      description: {
        part1: 'When an attachment is referenced by several notes, the first matching entry decides which note it belongs to.',
        part2: 'Insert each entry on a new line, highest priority first.',
        part3: 'An entry starting with a dot is a file extension, e.g.',
        part4: 'An entry starting with',
        part5: 'matches a frontmatter property, optionally with a value, e.g.',
        part6: 'Anything else is a path from the vault root, or a',
        part7: 'When no entry matches, or when the best entry matches several of the notes, the ambiguity is left to the mode above.',
        part8: 'If the setting is empty, every such attachment is left to the mode above, which is the behavior without this setting.',
        part9: 'Note that this can move an attachment into a note other than the one you ran the command on.'
      },
      name: 'Note priorities'
    },
    pages: {
      advanced: {
        description: 'Link format, display text, and the operation timeout.'
      },
      collectedAttachments: {
        description: 'How attachments are gathered into a note\'s folder, including network images and shared attachments.'
      },
      customTokens: {
        description: 'JavaScript tokens you define yourself for use in the path and file name templates.'
      },
      deletion: {
        description: 'What happens to orphan attachments and folders left empty.'
      },
      images: {
        description: 'Default size, JPEG conversion, and metadata handling for images.'
      },
      moveRenames: {
        description: 'How attachments follow their note when it is renamed or moved.'
      },
      path: {
        description: 'Which notes and folders the plugin acts on, and which extensions count as attachments.'
      },
      specialCharacters: {
        description: 'Characters stripped from generated names, and what replaces them.'
      }
    },
    renameAttachmentsToLowerCase: 'Rename attachments to lower case',
    renamedAttachmentFileName: {
      description: {
        part1: 'See available',
        part2: 'tokens',
        part3: 'Leave empty to keep the original attachment file name.'
      },
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
    shouldDeleteOrphanAttachments: {
      description: 'If enabled, when the note is deleted, its orphan attachments are deleted as well.',
      name: 'Should delete orphan attachments'
    },
    shouldHandleRenames: {
      description: {
        part1: 'Whether to handle renames.',
        part2: 'To handle embeds inside canvas text nodes on rename, additionally install the',
        part3: 'plugin. Canvas file node links are handled without it.'
      },
      name: 'Should handle renames'
    },
    shouldPreserveImageMetadata: {
      description: {
        part1: 'If enabled, the EXIF, GPS, XMP and ICC profile data of a converted image is carried into the JPEG. Only works when the original is already a JPEG; nothing else stores that data in a form that can be copied across.',
        part2: 'Enable it if you rely on the geolocation of your photos, for example to plot them on a map. Leave it off if you share your vault, since the same data also carries camera serial numbers and the times and places the photos were taken.',
        part3: 'The orientation is always reset, because the conversion has already rotated the pixels.'
      },
      name: 'Should preserve image metadata'
    },
    shouldRenameAttachmentFiles: {
      description: {
        part1: 'If enabled, when a note is renamed or moved, its attachments will be renamed according to the',
        part2: 'setting.'
      },
      name: 'Should rename attachment files'
    },
    shouldRenameAttachmentFolders: {
      description: 'Whether to rename attachment folders when a note is renamed or moved.',
      name: 'Should rename attachment folders'
    },
    shouldRenameAttachmentsCreatedByOtherPlugins: {
      description: {
        part1: 'Whether to apply the attachment folder and file name settings to attachments that OTHER plugins create.',
        part2: 'Some plugins write an attachment into the vault under a name of their own, without asking Obsidian where it belongs. With this enabled, such a file is moved and renamed right after it appears.',
        part3: 'Only files created while a note is open are touched, never files arriving from a sync or a vault import.'
      },
      name: 'Rename attachments created by other plugins'
    },
    shouldRenameCollectedAttachments: {
      description: {
        part1: 'If enabled, attachments processed via',
        part2: 'Collect attachments',
        part3: 'commands will be renamed according to the',
        part4: 'setting.'
      },
      name: 'Should rename collected attachments'
    },
    shouldRescueSharedAttachments: {
      description: {
        part1: 'If enabled, when a note or its attachment folder is deleted while another note still references one of its attachments, that attachment is moved into the surviving note\'s attachment folder instead of being left behind in the deleted note\'s folder. Its file name is kept.',
        part2: 'It moves only when a single note is left referencing the attachment, or when the',
        part3: 'setting names a clear winner among several. Otherwise the attachment stays where it is.',
        part4: 'Takes effect only while orphan attachments are deleted.'
      },
      name: 'Should rescue shared attachments'
    },
    shouldSetLinkDisplayTextToAttachmentFileName: {
      description: 'If enabled, when a link to an attachment is inserted, its display text is set to the attachment file name (without extension). Does not affect links between notes.',
      name: 'Set link display text to attachment file name'
    },
    shouldSkipCollectingAttachmentsReferencedByRawPath: {
      description: 'When collecting an attachment, also scan every note\'s raw text for the attachment\'s path or file name. If another note references it in a format Obsidian does not index (e.g. via other plugins\' custom syntaxes or raw HTML), the attachment is treated as still used and is left in place. This prevents losing attachments referenced by non-standard syntaxes, at the cost of a slower collect.',
      name: 'Skip collecting attachments referenced by a raw path'
    },
    specialCharacters: {
      description: {
        part1: 'Special characters in attachment folder and file name to be replaced or removed.',
        part2: 'Leave blank to preserve special characters.'
      },
      name: 'Special characters'
    },
    specialCharactersReplacement: {
      description: {
        part1: 'Replacement string for special characters in attachment folder and file name.',
        part2: 'Leave blank to remove special characters.'
      },
      name: 'Special characters replacement'
    },
    timeoutInSeconds: {
      description: {
        part1: 'The timeout in seconds for all operations.',
        part2: 'If',
        part3: 'is set, the operations execution timeout is disabled.'
      },
      name: 'Timeout in seconds'
    },
    treatAsAttachmentExtensions: {
      description: {
        part1: 'Treat files with these extensions as attachments.',
        part2: 'By default',
        part3: 'and',
        part4: 'linked files are not treated as attachments and are not moved with the note.',
        part5: 'You can add custom extensions, e.g.',
        part6: ', to override this behavior.',
        part7: 'Insert each extension on a new line.'
      },
      name: 'Treat as attachment extensions'
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
  regularExpression: '/regular expression/',
  releaseNotes: {
    title: 'Release notes',
    versionMismatch: {
      part1: 'Your settings file ',
      part2: 'has version',
      part3: 'which is newer than the current plugin version',
      part4: 'The plugin might not work as expected. Please update the plugin to the latest version or ensure that the settings are correct.',
      title: 'Version mismatch'
    },
    versions: {
      '10.0.0': {
        part1: 'The format of tokens has been changed. Please update your tokens accordingly. See',
        part2: 'documentation',
        part3: 'for more information.'
      },
      '11.0.0': {
        part1: 'Custom tokens that read the attachment content must be updated. The synchronous',
        part2: 'property was replaced with the lazy',
        part3: 'method. See',
        part4: 'documentation',
        part5: 'for migration details.'
      }
    }
  }
} as const satisfies DefaultTranslationsBase;
