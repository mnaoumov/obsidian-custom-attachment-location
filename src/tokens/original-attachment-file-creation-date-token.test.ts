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
import { OriginalAttachmentFileCreationDateToken } from './original-attachment-file-creation-date-token.ts';

const CTIME = Date.UTC(2019, 2, 4, 5, 6, 7);

function createContext(
  attachmentFileStats: FileStats | undefined,
  format: TokenEvaluatorContext['format']
): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    attachmentFileStats,
    format
  });
}

describe('OriginalAttachmentFileCreationDateToken', () => {
  it('should be named originalAttachmentFileCreationDate', () => {
    const token = new OriginalAttachmentFileCreationDateToken();
    expect(token.name).toBe('originalAttachmentFileCreationDate');
  });

  it('should format the attachment creation date when known', () => {
    const token = new OriginalAttachmentFileCreationDateToken();
    const stats = strictProxy<FileStats>({ ctime: CTIME });
    const result = token.evaluate(createContext(stats, { momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe(moment(CTIME).format('YYYY-MM-DD'));
  });

  it('should return an empty string when unknown and valueWhenUnknown is empty', () => {
    const token = new OriginalAttachmentFileCreationDateToken();
    const result = token.evaluate(createContext(undefined, { momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe('');
  });

  it('should return the current time when unknown and valueWhenUnknown is now', () => {
    const token = new OriginalAttachmentFileCreationDateToken();
    const result = token.evaluate(createContext(undefined, { momentJsFormat: '[constant]', valueWhenUnknown: 'now' }));
    expect(result).toBe('constant');
  });
});
