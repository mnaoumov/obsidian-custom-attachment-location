import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { OriginalAttachmentFileNameToken } from './original-attachment-file-name-token.ts';

function createContext(originalAttachmentFileName: string, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format,
    originalAttachmentFileName
  });
}

describe('OriginalAttachmentFileNameToken', () => {
  it('should be named originalAttachmentFileName', () => {
    const token = new OriginalAttachmentFileNameToken();
    expect(token.name).toBe('originalAttachmentFileName');
  });

  it('should return the original attachment file name unchanged by default', () => {
    const token = new OriginalAttachmentFileNameToken();
    const result = token.evaluate(createContext('image', null));
    expect(result).toBe('image');
  });

  it('should apply the string format', () => {
    const token = new OriginalAttachmentFileNameToken();
    const result = token.evaluate(createContext('Image Name', { case: 'lower' }));
    expect(result).toBe('image name');
  });
});
