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
  let handler: CollectAttachmentsEntireVaultCommandHandler;

  beforeEach(() => {
    vi.clearAllMocks();
    attachmentCollector = createAttachmentCollector();
    handler = new CollectAttachmentsEntireVaultCommandHandler({ attachmentCollector });
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(CollectAttachmentsEntireVaultCommandHandler);
    expect(toTestable(handler).id).toBe('collect-attachments-entire-vault');
    expect(toTestable(handler).icon).toBe('download');
    expect(toTestable(handler).name).toBe('Collect attachments in entire vault');
  });

  it('should delegate to the attachment collector on execute', async () => {
    await toTestable(handler).execute();
    expect(mockCollectAttachmentsEntireVault).toHaveBeenCalledOnce();
  });
});
