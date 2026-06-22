import { castTo } from 'obsidian-dev-utils/object-utils';
import { initI18N } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentCollector } from '../attachment-collector.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { CollectAttachmentsEntireVaultCommandHandler } from './collect-attachments-entire-vault-command-handler.ts';

interface TestableHandler {
  execute(): Promise<void>;
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
  let handler: CollectAttachmentsEntireVaultCommandHandler;

  beforeEach(() => {
    vi.clearAllMocks();
    attachmentCollector = createAttachmentCollector();
    handler = new CollectAttachmentsEntireVaultCommandHandler({ attachmentCollector });
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(CollectAttachmentsEntireVaultCommandHandler);
    expect(handler.id).toBe('collect-attachments-entire-vault');
    expect(handler.icon).toBe('download');
    expect(handler.name).toBe('Collect attachments in entire vault');
  });

  it('should delegate to the attachment collector on execute', async () => {
    await toTestable(handler).execute();
    expect(mockCollectAttachmentsEntireVault).toHaveBeenCalledOnce();
  });
});
