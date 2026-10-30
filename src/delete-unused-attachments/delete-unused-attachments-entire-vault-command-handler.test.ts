import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { App } from 'obsidian';

import { BulkOperationCommitComponent } from '@mnaoumov/obsidian-lib/components/bulk-operation-commit-component';
import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { UnusedAttachmentsRemover } from './unused-attachments-remover.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { DeleteUnusedAttachmentsEntireVaultCommandHandler } from './delete-unused-attachments-entire-vault-command-handler.ts';

interface TestableHandler {
  readonly execute: () => Promise<void>;
  readonly icon: string;
  readonly id: string;
  readonly name: string;
}

const mockDeleteUnusedAttachmentsEntireVault = vi.fn<UnusedAttachmentsRemover['deleteUnusedAttachmentsEntireVault']>();

function createUnusedAttachmentsRemover(): UnusedAttachmentsRemover {
  return strictProxy<UnusedAttachmentsRemover>({
    deleteUnusedAttachmentsEntireVault: mockDeleteUnusedAttachmentsEntireVault
  });
}

function toTestable(handler: DeleteUnusedAttachmentsEntireVaultCommandHandler): TestableHandler {
  return castTo<TestableHandler>(handler);
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('DeleteUnusedAttachmentsEntireVaultCommandHandler', () => {
  let bulkOperationCommitComponent: BulkOperationCommitComponent;
  let handler: DeleteUnusedAttachmentsEntireVaultCommandHandler;
  let unusedAttachmentsRemover: UnusedAttachmentsRemover;

  beforeEach(() => {
    vi.clearAllMocks();
    unusedAttachmentsRemover = createUnusedAttachmentsRemover();
    // The real component with its setting off, which runs the operation as it is.
    bulkOperationCommitComponent = new BulkOperationCommitComponent({
      app: strictProxy<App>({}),
      isEnabled: (): boolean => false,
      pluginId: 'test-plugin',
      pluginNoticeComponent: strictProxy<PluginNoticeComponent>({})
    });
    handler = new DeleteUnusedAttachmentsEntireVaultCommandHandler({ bulkOperationCommitComponent, unusedAttachmentsRemover });
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(DeleteUnusedAttachmentsEntireVaultCommandHandler);
    // A command id of its own: the per-note command keeps its meaning, so a hotkey bound to it can
    // never turn into a whole-vault deletion.
    expect(toTestable(handler).id).toBe('delete-unused-attachments-entire-vault');
    expect(toTestable(handler).icon).toBe('trash-2');
    expect(toTestable(handler).name).toBe('Delete unused attachments in entire vault');
  });

  it('should delegate to the unused attachments remover on execute, as one bulk operation', async () => {
    const runBulkOperationSpy = vi.spyOn(bulkOperationCommitComponent, 'runBulkOperation');
    await toTestable(handler).execute();
    expect(mockDeleteUnusedAttachmentsEntireVault).toHaveBeenCalledOnce();
    expect(runBulkOperationSpy.mock.calls[0]?.[0].summary).toBe('Delete unused attachments in entire vault');
  });
});
