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

import type { UnusedAttachmentsRemover } from '../unused-attachments-remover.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { DeleteUnusedAttachmentsEntireVaultCommandHandler } from './delete-unused-attachments-entire-vault-command-handler.ts';

interface TestableHandler {
  execute(): Promise<void>;
  icon: string;
  id: string;
  name: string;
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
  let handler: DeleteUnusedAttachmentsEntireVaultCommandHandler;
  let unusedAttachmentsRemover: UnusedAttachmentsRemover;

  beforeEach(() => {
    vi.clearAllMocks();
    unusedAttachmentsRemover = createUnusedAttachmentsRemover();
    handler = new DeleteUnusedAttachmentsEntireVaultCommandHandler({ unusedAttachmentsRemover });
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(DeleteUnusedAttachmentsEntireVaultCommandHandler);
    // A command id of its own: the per-note command keeps its meaning, so a hotkey bound to it can
    // Never turn into a whole-vault deletion.
    expect(toTestable(handler).id).toBe('delete-unused-attachments-entire-vault');
    expect(toTestable(handler).icon).toBe('trash-2');
    expect(toTestable(handler).name).toBe('Delete unused attachments in entire vault');
  });

  it('should delegate to the unused attachments remover on execute', async () => {
    await toTestable(handler).execute();
    expect(mockDeleteUnusedAttachmentsEntireVault).toHaveBeenCalledOnce();
  });
});
