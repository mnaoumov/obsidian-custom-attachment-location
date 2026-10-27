import type {
  ApiMethodCases,
  PayloadCases
} from '@mnaoumov/typescript-lib/api-contract-verifier';

import {
  validateSync,
  verifyApiContract
} from '@mnaoumov/typescript-lib/api-contract-verifier';
import {
  App,
  TFile,
  TFolder
} from 'obsidian-test-mocks/obsidian';
import {
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { CustomAttachmentLocationApi } from '../../api.d.ts';

import { CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT } from '../../api-contract.ts';

const app = App.createConfigured__();
const file = TFile.create__(app.vault, 'Notes/Alpha.md').asOriginalType__();
const folder = TFolder.create__(app.vault, 'Notes').asOriginalType__();

const AVAILABLE_PATH_PARAMS = {
  attachmentFileBaseName: 'image',
  attachmentFileExtension: 'png',
  context: 'RenameNote',
  notePathOrFile: 'Notes/Renamed.md',
  oldAttachmentPathOrFile: 'Attachments/Alpha/image.png',
  oldNotePathOrFile: 'Notes/Alpha.md',
  readAttachmentFileContent: null,
  shouldSkipMissingAttachmentFolderCreation: true
};

const NULL_OR_STRING: PayloadCases = { invalid: [undefined, 1, false], valid: [null, '', 'Attachments/Alpha'] };

const CASES: Record<keyof CustomAttachmentLocationApi, ApiMethodCases> = {
  collectAttachments: {
    input: {
      invalid: [[], [null], [{}], [{ pathsOrFiles: 'Notes/Alpha.md' }], [{ pathsOrFiles: [1] }], [{ pathsOrFiles: [] }, 'extra'], { pathsOrFiles: [] }],
      valid: [[{ pathsOrFiles: [] }], [{ pathsOrFiles: ['Notes/Alpha.md', file, folder] }]]
    },
    output: { invalid: [null, false, ''], valid: [undefined] }
  },
  getAttachmentFolderPath: {
    input: {
      invalid: [[], [{}], [{ notePath: 1 }], [{ attachmentFileName: 1, notePath: 'Notes/Alpha.md' }]],
      valid: [[{ notePath: 'Notes/Alpha.md' }], [{ attachmentFileName: 'image.png', notePath: 'Notes/Alpha.md' }], [{
        attachmentFileName: undefined,
        notePath: 'Notes/Alpha.md'
      }]]
    },
    output: NULL_OR_STRING
  },
  getAvailablePathForAttachments: {
    input: {
      invalid: [
        [],
        [{ ...AVAILABLE_PATH_PARAMS, context: 'Save' }],
        [{ ...AVAILABLE_PATH_PARAMS, notePathOrFile: folder }],
        [{ ...AVAILABLE_PATH_PARAMS, oldAttachmentPathOrFile: null }],
        [{ ...AVAILABLE_PATH_PARAMS, readAttachmentFileContent: undefined }],
        [{ ...AVAILABLE_PATH_PARAMS, attachmentFileStats: { ctime: 1, mtime: 2 } }],
        [{ ...AVAILABLE_PATH_PARAMS, shouldSkipDuplicateCheck: 'yes' }],
        [{ ...AVAILABLE_PATH_PARAMS, attachmentFileBaseName: undefined }]
      ],
      valid: [
        [AVAILABLE_PATH_PARAMS],
        [{
          ...AVAILABLE_PATH_PARAMS,
          attachmentFileStats: { ctime: 1, mtime: 2, size: 3 },
          context: 'Unknown',
          notePathOrFile: null,
          oldAttachmentPathOrFile: file,
          oldNotePathOrFile: file,
          readAttachmentFileContent: vi.fn<() => Promise<ArrayBuffer>>(),
          shouldSkipDuplicateCheck: true,
          shouldSkipGeneratedAttachmentFileName: false,
          shouldSkipMissingAttachmentFolderCreation: undefined
        }]
      ]
    },
    output: { invalid: [null, undefined, 1], valid: ['Attachments/Alpha/image.png'] }
  },
  getProperAttachmentPath: {
    input: {
      invalid: [[], [{ notePath: 'Notes/Alpha.md' }], [{ attachmentPathOrFile: folder, notePath: 'Notes/Alpha.md' }]],
      valid: [[{ attachmentPathOrFile: 'image.png', notePath: 'Notes/Alpha.md' }], [{ attachmentPathOrFile: file, notePath: 'Notes/Alpha.md' }]]
    },
    output: NULL_OR_STRING
  },
  isAttachmentUnitFolder: {
    input: {
      invalid: [[], ['Notes/page_files'], [{ folderPath: null }]],
      // A key the params do not name is let through, as before the guards moved to `@mnaoumov/typescript-lib`.
      valid: [[{ folderPath: 'Notes/page_files' }], [{ folderPath: 'Notes/page_files', unknownKey: true }]]
    },
    output: { invalid: [null, undefined, 'true'], valid: [true, false] }
  },
  migrateSettings: {
    input: {
      invalid: [
        [],
        [{ proposedSettings: {} }],
        [{ proposedSettings: null, sourcePluginId: 'consistent-attachments-and-links' }],
        [{ proposedSettings: { collectAttachmentUsedByMultipleNotesMode: 'CopyAll' }, sourcePluginId: 'consistent-attachments-and-links' }],
        [{ proposedSettings: { moveAttachmentToProperFolderUsedByMultipleNotesMode: 'Copy' }, sourcePluginId: 'consistent-attachments-and-links' }],
        [{ proposedSettings: { attachmentUnitFolderPaths: [1] }, sourcePluginId: 'consistent-attachments-and-links' }],
        [{ proposedSettings: { shouldCollectAttachmentsAutomatically: 'yes' }, sourcePluginId: 'consistent-attachments-and-links' }]
      ],
      valid: [
        [{ proposedSettings: {}, sourcePluginId: 'consistent-attachments-and-links' }],
        [{
          proposedSettings: {
            attachmentUnitFolderPaths: ['/_files$/'],
            collectAttachmentUsedByMultipleNotesMode: 'Copy',
            excludePathsFromAttachmentCollecting: [],
            moveAttachmentToProperFolderUsedByMultipleNotesMode: 'CopyAll',
            shouldCollectAttachmentsAutomatically: true
          },
          sourcePluginId: 'consistent-attachments-and-links'
        }]
      ]
    },
    output: { invalid: [null, undefined, true, {}, { isApplied: 'yes' }], valid: [{ isApplied: true }, { isApplied: false }] }
  }
};

describe('CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT', () => {
  it('should pass the contract verification', async () => {
    expect(await verifyApiContract(CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT, { cases: CASES, vendor: 'obsidian-custom-attachment-location' })).toEqual([]);
  });

  it('should name the failing argument and what it expected', () => {
    expect(validateSync(CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT.isAttachmentUnitFolder.input, [{ folderPath: 1 }])).toEqual({
      issues: [{ message: 'Expected attachment-unit-folder params: { folderPath: string }.', path: [0] }]
    });
    expect(validateSync(CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT.isAttachmentUnitFolder.input, 'Notes')).toEqual({
      issues: [{ message: 'Expected an argument list.' }]
    });
    expect(validateSync(CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT.isAttachmentUnitFolder.input, [{ folderPath: 'a' }, 'b'])).toEqual({
      issues: [{ message: 'Expected at most 1 argument(s), got 2.' }]
    });
    expect(validateSync(CUSTOM_ATTACHMENT_LOCATION_API_CONTRACT.migrateSettings.output, null)).toEqual({
      issues: [{ message: 'Expected a migrate-settings result: { isApplied: boolean }.' }]
    });
  });
});
