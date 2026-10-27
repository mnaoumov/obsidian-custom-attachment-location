import type { ApiMethodContract } from '@mnaoumov/typescript-lib/api-contract';

import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type {
  AdvancedRenameAndDeleteHandlerApi,
  HandedOverSettings
} from './api.d.ts';

import { ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT } from './api-contract.ts';

interface MethodCases {
  readonly input: PayloadCase;
  readonly output: PayloadCase;
}

type MethodName = keyof AdvancedRenameAndDeleteHandlerApi;

interface PayloadCase {
  readonly invalid: readonly unknown[];
  readonly valid: readonly unknown[];
}

type Schema = NonNullable<ApiMethodContract['input']>;

type SchemaResult = Awaited<ReturnType<Schema['~standard']['validate']>>;

const SETTINGS: HandedOverSettings = {
  emptyFolderBehavior: 'DeleteWithEmptyParents',
  excludePaths: ['Archive'],
  includePaths: [],
  notePriorities: ['.md'],
  shouldDeleteConflictingAttachments: false,
  shouldDeleteEmptyNoteFolders: false,
  shouldHandleDeletions: true,
  shouldHandleRenames: true,
  shouldRenameAttachmentFiles: false,
  shouldRenameAttachmentFolder: true,
  shouldRescueSharedAttachments: false,
  shouldUpdateFileNameAliases: true,
  treatAsAttachmentExtensions: ['.excalidraw.md', 'property:excalidraw-plugin']
};

const PATH: PayloadCase = { invalid: [[], [1], [null], ['a.md', 'extra'], 'a.md'], valid: [['a.md'], ['']] };
const BOOLEAN: PayloadCase = { invalid: [undefined, null, 'true', 0], valid: [true, false] };

const CASES: Record<MethodName, MethodCases> = {
  getSettings: {
    input: { invalid: [['extra'], null, {}], valid: [[]] },
    output: {
      invalid: [
        null,
        {},
        [],
        { ...SETTINGS, emptyFolderBehavior: 'delete' },
        { ...SETTINGS, emptyFolderBehavior: 'toString' },
        { ...SETTINGS, excludePaths: 'Archive' },
        { ...SETTINGS, includePaths: [1] },
        { ...SETTINGS, notePriorities: undefined },
        { ...SETTINGS, shouldHandleDeletions: 'yes' },
        { ...SETTINGS, shouldUpdateFileNameAliases: undefined },
        { ...SETTINGS, treatAsAttachmentExtensions: null }
      ],
      valid: [
        SETTINGS,
        { ...SETTINGS, emptyFolderBehavior: 'Keep' },
        { ...SETTINGS, emptyFolderBehavior: 'Delete' },
        // A key that names no setting is let through, as before the guards moved to `@mnaoumov/typescript-lib`.
        { ...SETTINGS, unknownSetting: 1 }
      ]
    }
  },
  isPathIgnored: { input: PATH, output: BOOLEAN },
  isTreatedAsAttachment: { input: PATH, output: BOOLEAN },
  migrateSettings: {
    input: {
      invalid: [
        [],
        [null],
        [{ proposedSettings: {} }],
        [{ proposedSettings: null, sourcePluginId: 'x' }],
        [{ proposedSettings: {}, sourcePluginId: 1 }],
        [{ proposedSettings: { shouldHandleRenames: 'yes' }, sourcePluginId: 'x' }],
        [{ proposedSettings: { emptyFolderBehavior: 'Remove' }, sourcePluginId: 'x' }],
        [{ proposedSettings: { notePriorities: [1] }, sourcePluginId: 'x' }]
      ],
      valid: [
        [{ proposedSettings: {}, sourcePluginId: 'x' }],
        [{ proposedSettings: SETTINGS, sourcePluginId: 'x' }],
        [{ proposedSettings: { shouldHandleRenames: undefined, treatAsAttachmentExtensions: ['.excalidraw.md'] }, sourcePluginId: 'x' }],
        [{ proposedSettings: { unknownSetting: 1 }, sourcePluginId: 'x' }]
      ]
    },
    output: { invalid: [null, {}, { isApplied: 'yes' }], valid: [{ isApplied: true }, { isApplied: false }] }
  }
};

describe('ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT', () => {
  it('should have one entry per method of the API, each with both schemas', () => {
    expect(Object.keys(ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT).sort()).toEqual(Object.keys(CASES).sort());
    for (const methodName of castTo<MethodName[]>(Object.keys(ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT))) {
      const methodContract = ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT[methodName];
      for (const schema of [methodContract.input, methodContract.output]) {
        expect(schema['~standard']).toMatchObject({ vendor: 'advanced-rename-and-delete-handler', version: 1 });
      }
    }
  });

  it('should accept every valid payload and refuse every invalid one', async () => {
    for (const methodName of castTo<MethodName[]>(Object.keys(CASES))) {
      for (const half of ['input', 'output'] as const) {
        const schema: Schema = ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT[methodName][half];
        const { invalid, valid } = CASES[methodName][half];
        for (const [index, value] of valid.entries()) {
          expect(await validate(schema, value), `${methodName} ${half} should accept valid case ${String(index)}`).toEqual({ value });
        }

        for (const [index, value] of invalid.entries()) {
          const result = await validate(schema, value);
          expect(result.issues, `${methodName} ${half} should refuse invalid case ${String(index)}`).not.toHaveLength(0);
        }
      }
    }
  });

  it('should name the failing argument and what it expected', async () => {
    expect(await validate(ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.isPathIgnored.input, [1])).toEqual({
      issues: [{ message: 'Expected a path.', path: [0] }]
    });
    expect(await validate(ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.isPathIgnored.input, 'a.md')).toEqual({
      issues: [{ message: 'Expected an argument list.' }]
    });
    expect(await validate(ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.isPathIgnored.input, ['a', 'b'])).toEqual({
      issues: [{ message: 'Expected at most 1 argument(s), got 2.' }]
    });
    expect(await validate(ADVANCED_RENAME_AND_DELETE_HANDLER_API_CONTRACT.getSettings.output, null)).toEqual({
      issues: [{ message: 'Expected the handed-over settings.' }]
    });
  });
});

async function validate(schema: Schema, value: unknown): Promise<SchemaResult> {
  return await schema['~standard'].validate(value);
}
