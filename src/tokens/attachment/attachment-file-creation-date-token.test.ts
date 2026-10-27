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

import { AttachmentFileCreationDateToken } from './attachment-file-creation-date-token.ts';

const moment = extractDefaultExportInterop(moment_);

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

describe('AttachmentFileCreationDateToken', () => {
  it('should be named attachmentFileCreationDate', () => {
    const token = new AttachmentFileCreationDateToken();
    expect(token.name).toBe('attachmentFileCreationDate');
  });

  it('should format the attachment creation date when known', () => {
    const token = new AttachmentFileCreationDateToken();
    const stats = strictProxy<FileStats>({ ctime: CTIME });
    const result = token.evaluate(createContext(stats, { momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe(moment(CTIME).format('YYYY-MM-DD'));
  });

  it('should return an empty string when unknown and valueWhenUnknown is empty', () => {
    const token = new AttachmentFileCreationDateToken();
    const result = token.evaluate(createContext(undefined, { momentJsFormat: 'YYYY-MM-DD' }));
    expect(result).toBe('');
  });

  it('should return the current time when unknown and valueWhenUnknown is now', () => {
    const token = new AttachmentFileCreationDateToken();
    const result = token.evaluate(createContext(undefined, { momentJsFormat: '[constant]', valueWhenUnknown: 'now' }));
    expect(result).toBe('constant');
  });
});
