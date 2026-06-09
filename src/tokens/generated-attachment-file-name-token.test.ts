import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { GeneratedAttachmentFileNameToken } from './generated-attachment-file-name-token.ts';

function createContext(generatedAttachmentFileName: string, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format,
    generatedAttachmentFileName
  });
}

describe('GeneratedAttachmentFileNameToken', () => {
  it('should be named generatedAttachmentFileName', () => {
    const token = new GeneratedAttachmentFileNameToken();
    expect(token.name).toBe('generatedAttachmentFileName');
  });

  it('should return the generated attachment file name unchanged by default', () => {
    const token = new GeneratedAttachmentFileNameToken();
    const result = token.evaluate(createContext('generated', null));
    expect(result).toBe('generated');
  });

  it('should apply the string format', () => {
    const token = new GeneratedAttachmentFileNameToken();
    const result = token.evaluate(createContext('Generated Name', { case: 'upper' }));
    expect(result).toBe('GENERATED NAME');
  });
});
