import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { AttachmentFileExtensionToken } from './attachment-file-extension-token.ts';

function createContext(attachmentFileExtension: string): TokenEvaluatorContext {
  return strictProxy<TokenEvaluatorContext>({
    attachmentFileExtension,
    format: null
  });
}

describe('AttachmentFileExtensionToken', () => {
  it('should be named attachmentFileExtension', () => {
    const token = new AttachmentFileExtensionToken();
    expect(token.name).toBe('attachmentFileExtension');
  });

  it('should return the attachment file extension', () => {
    const token = new AttachmentFileExtensionToken();
    const result = token.evaluate(createContext('png'));
    expect(result).toBe('png');
  });
});
