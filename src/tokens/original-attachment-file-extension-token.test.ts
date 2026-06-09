import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { OriginalAttachmentFileExtensionToken } from './original-attachment-file-extension-token.ts';

function createContext(originalAttachmentFileExtension: string): TokenEvaluatorContext {
  return strictProxy<TokenEvaluatorContext>({
    format: null,
    originalAttachmentFileExtension
  });
}

describe('OriginalAttachmentFileExtensionToken', () => {
  it('should be named originalAttachmentFileExtension', () => {
    const token = new OriginalAttachmentFileExtensionToken();
    expect(token.name).toBe('originalAttachmentFileExtension');
  });

  it('should return the original attachment file extension', () => {
    const token = new OriginalAttachmentFileExtensionToken();
    const result = token.evaluate(createContext('png'));
    expect(result).toBe('png');
  });
});
