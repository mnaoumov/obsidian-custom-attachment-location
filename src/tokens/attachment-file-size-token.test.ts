import type { Promisable } from 'type-fest';

import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { AttachmentFileSizeToken } from './attachment-file-size-token.ts';

interface EvaluateImplFormat {
  decimalPoints: number;
  unit: 'B' | 'KB' | 'MB';
}

class TestableAttachmentFileSizeToken extends AttachmentFileSizeToken {
  public callEvaluateImpl(ctx: TokenEvaluatorContext, format: EvaluateImplFormat): Promisable<string> {
    return this.evaluateImpl(ctx, format);
  }
}

function createContext(byteLength: number | undefined, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    attachmentFileContent: byteLength === undefined ? undefined : new ArrayBuffer(byteLength),
    format
  });
}

describe('AttachmentFileSizeToken', () => {
  it('should be named attachmentFileSize', () => {
    const token = new AttachmentFileSizeToken();
    expect(token.name).toBe('attachmentFileSize');
  });

  it('should report 0 bytes when there is no attachment content', () => {
    const token = new AttachmentFileSizeToken();
    const result = token.evaluate(createContext(undefined, null));
    expect(result).toBe('0');
  });

  it('should report bytes by default', () => {
    const token = new AttachmentFileSizeToken();
    const result = token.evaluate(createContext(2048, null));
    expect(result).toBe('2048');
  });

  it('should report kilobytes with decimal points', () => {
    const token = new AttachmentFileSizeToken();
    const result = token.evaluate(createContext(2048, { decimalPoints: 2, unit: 'KB' }));
    expect(result).toBe('2.00');
  });

  it('should report megabytes with decimal points', () => {
    const token = new AttachmentFileSizeToken();
    const result = token.evaluate(createContext(1024 * 1024 * 3, { decimalPoints: 1, unit: 'MB' }));
    expect(result).toBe('3.0');
  });

  it('should reject an invalid unit through the schema', () => {
    const token = new AttachmentFileSizeToken();
    const format = castTo<TokenEvaluatorContext['format']>({ decimalPoints: 0, unit: 'GB' });
    expect(() => token.evaluate(createContext(1024, format))).toThrow();
  });

  it('should throw on an invalid unit reaching the evaluator directly', () => {
    const token = new TestableAttachmentFileSizeToken();
    const format = castTo<EvaluateImplFormat>({ decimalPoints: 0, unit: 'GB' });
    expect(() => token.callEvaluateImpl(createContext(1024, null), format)).toThrow('Invalid file size unit: GB');
  });
});
