import type { FileStats } from 'obsidian';

import {
  castTo,
  extractDefaultExportInterop
} from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { moment as moment_ } from 'obsidian';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { AttachmentFileModificationDateToken } from './attachment-file-modification-date-token.ts';

const moment = extractDefaultExportInterop(moment_);

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

describe('AttachmentFileModificationDateToken', () => {
  it('should be named attachmentFileModificationDate', () => {
    const token = new AttachmentFileModificationDateToken();
    expect(token.name).toBe('attachmentFileModificationDate');
  });

  it('should format the attachment modification date when known', () => {
    const token = new AttachmentFileModificationDateToken();
    const stats = strictProxy<FileStats>({ mtime: MTIME });
    const result = token.evaluate(createContext(stats, { momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe(moment(MTIME).format('YYYY-MM-DD'));
  });

  it('should return an empty string when unknown and valueWhenUnknown is empty', () => {
    const token = new AttachmentFileModificationDateToken();
    const result = token.evaluate(createContext(undefined, { momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe('');
  });

  it('should return the current time when unknown and valueWhenUnknown is now', () => {
    const token = new AttachmentFileModificationDateToken();
    const result = token.evaluate(createContext(undefined, { momentJsFormat: '[constant]', valueWhenUnknown: 'now' }));
    expect(result).toBe('constant');
  });
});
