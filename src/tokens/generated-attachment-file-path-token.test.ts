import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { GeneratedAttachmentFilePathToken } from './generated-attachment-file-path-token.ts';

function createContext(generatedAttachmentFilePath: string): TokenEvaluatorContext {
  return strictProxy<TokenEvaluatorContext>({
    format: null,
    generatedAttachmentFilePath
  });
}

describe('GeneratedAttachmentFilePathToken', () => {
  it('should be named generatedAttachmentFilePath', () => {
    const token = new GeneratedAttachmentFilePathToken();
    expect(token.name).toBe('generatedAttachmentFilePath');
  });

  it('should return the generated attachment file path', () => {
    const token = new GeneratedAttachmentFilePathToken();
    const result = token.evaluate(createContext('attachments/file.png'));
    expect(result).toBe('attachments/file.png');
  });
});
