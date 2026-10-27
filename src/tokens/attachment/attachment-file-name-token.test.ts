import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { AttachmentFileNameToken } from './attachment-file-name-token.ts';

function createContext(attachmentFileName: string, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    attachmentFileName,
    format
  });
}

describe('AttachmentFileNameToken', () => {
  it('should be named attachmentFileName', () => {
    const token = new AttachmentFileNameToken();
    expect(token.name).toBe('attachmentFileName');
  });

  it('should return the attachment file name unchanged by default', () => {
    const token = new AttachmentFileNameToken();
    const result = token.evaluate(createContext('image', null));
    expect(result).toBe('image');
  });

  it('should apply the string format', () => {
    const token = new AttachmentFileNameToken();
    const result = token.evaluate(createContext('Image Name', { case: 'lower' }));
    expect(result).toBe('image name');
  });
});
