import type { FileStats } from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { moment } from './moment-js-token-base.ts';
import { OriginalAttachmentFileModificationDateToken } from './original-attachment-file-modification-date-token.ts';

const MTIME = Date.UTC(2018, 7, 9, 10, 11, 12);

function createContext(
  attachmentFileStats: FileStats | undefined,
  format: TokenEvaluatorContext['format']
): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    attachmentFileStats,
    format
  });
}

describe('OriginalAttachmentFileModificationDateToken', () => {
  it('should be named originalAttachmentFileModificationDate', () => {
    const token = new OriginalAttachmentFileModificationDateToken();
    expect(token.name).toBe('originalAttachmentFileModificationDate');
  });

  it('should format the attachment modification date when known', () => {
    const token = new OriginalAttachmentFileModificationDateToken();
    const stats = strictProxy<FileStats>({ mtime: MTIME });
    const result = token.evaluate(createContext(stats, { momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe(moment(MTIME).format('YYYY-MM-DD'));
  });

  it('should return an empty string when unknown and valueWhenUnknown is empty', () => {
    const token = new OriginalAttachmentFileModificationDateToken();
    const result = token.evaluate(createContext(undefined, { momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe('');
  });

  it('should return the current time when unknown and valueWhenUnknown is now', () => {
    const token = new OriginalAttachmentFileModificationDateToken();
    const result = token.evaluate(createContext(undefined, { momentJsFormat: '[constant]', valueWhenUnknown: 'now' }));
    expect(result).toBe('constant');
  });
});
