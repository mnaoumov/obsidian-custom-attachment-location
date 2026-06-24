import type { TFolder } from 'obsidian';

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
import { CollectAttachmentsInCurrentFolderCommandHandler } from './collect-attachments-in-current-folder-command-handler.ts';

interface TestableHandler {
  executeFolder(folder: TFolder): void;
  icon: string;
  id: string;
  name: string;
}

const mockCollectAttachmentsInAbstractFiles = vi.fn<AttachmentCollector['collectAttachmentsInAbstractFiles']>();

function createAttachmentCollector(): AttachmentCollector {
  return strictProxy<AttachmentCollector>({
    collectAttachmentsInAbstractFiles: mockCollectAttachmentsInAbstractFiles
  });
}

function toTestable(handler: CollectAttachmentsInCurrentFolderCommandHandler): TestableHandler {
  return castTo<TestableHandler>(handler);
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

describe('CollectAttachmentsInCurrentFolderCommandHandler', () => {
  let attachmentCollector: AttachmentCollector;
  let handler: CollectAttachmentsInCurrentFolderCommandHandler;

  beforeEach(() => {
    vi.clearAllMocks();
    attachmentCollector = createAttachmentCollector();
    handler = new CollectAttachmentsInCurrentFolderCommandHandler({ attachmentCollector });
  });

  it('should construct with the correct command metadata', () => {
    expect(handler).toBeInstanceOf(CollectAttachmentsInCurrentFolderCommandHandler);
    expect(toTestable(handler).id).toBe('collect-attachments-in-current-folder');
    expect(toTestable(handler).icon).toBe('download');
    expect(toTestable(handler).name).toBe('Collect attachments in current folder');
  });

  it('should delegate the folder wrapped in an array to the attachment collector on executeFolder', () => {
    const folder = strictProxy<TFolder>({ path: 'folder' });
    toTestable(handler).executeFolder(folder);
    expect(mockCollectAttachmentsInAbstractFiles).toHaveBeenCalledExactlyOnceWith([folder]);
  });
});
