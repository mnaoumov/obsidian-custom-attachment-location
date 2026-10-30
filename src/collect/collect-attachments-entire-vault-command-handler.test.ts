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

import type { AttachmentCollector } from './attachment-collector.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { CollectAttachmentsEntireVaultCommandHandler } from './collect-attachments-entire-vault-command-handler.ts';

interface TestableHandler {
  readonly execute: () => Promise<void>;
  readonly icon: string;
  readonly id: string;
  readonly name: string;
}

const mockCollectAttachmentsEntireVault = vi.fn<AttachmentCollector['collectAttachmentsEntireVault']>();

function createAttachmentCollector(): AttachmentCollector {
  return strictProxy<AttachmentCollector>({
    collectAttachmentsEntireVault: mockCollectAttachmentsEntireVault
  });
}

function toTestable(handler: CollectAttachmentsEntireVaultCommandHandler): TestableHandler {
  return castTo<TestableHandler>(handler);
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('CollectAttachmentsEntireVaultCommandHandler', () => {
  let attachmentCollector: AttachmentCollector;
  let bulkOperationCommitComponent: BulkOperationCommitComponent;
  let handler: CollectAttachmentsEntireVaultCommandHandler;

  beforeEach(() => {
    vi.clearAllMocks();
    attachmentCollector = createAttachmentCollector();
    // The real component with its setting off, which runs the operation as it is.
    bulkOperationCommitComponent = new BulkOperationCommitComponent({
      app: strictProxy<App>({}),
      isEnabled: (): boolean => false,
      pluginId: 'test-plugin',
      pluginNoticeComponent: strictProxy<PluginNoticeComponent>({})
    });
    handler = new CollectAttachmentsEntireVaultCommandHandler({ attachmentCollector, bulkOperationCommitComponent });
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(CollectAttachmentsEntireVaultCommandHandler);
    expect(toTestable(handler).id).toBe('collect-attachments-entire-vault');
    expect(toTestable(handler).icon).toBe('download');
    expect(toTestable(handler).name).toBe('Collect attachments in entire vault');
  });

  it('should delegate to the attachment collector on execute, as one bulk operation', async () => {
    const runBulkOperationSpy = vi.spyOn(bulkOperationCommitComponent, 'runBulkOperation');
    await toTestable(handler).execute();
    expect(mockCollectAttachmentsEntireVault).toHaveBeenCalledOnce();
    expect(runBulkOperationSpy.mock.calls[0]?.[0].summary).toBe('Collect attachments in entire vault');
  });
});
