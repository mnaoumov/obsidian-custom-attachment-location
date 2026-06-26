import type { Promisable } from 'type-fest';

import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it,
  vi
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
    format,
    getAttachmentFileContent: () => Promise.resolve(byteLength === undefined ? undefined : new ArrayBuffer(byteLength))
  });
}

function createStatsContext(size: number, byteLength: number | undefined, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    attachmentFileStats: { ctime: 0, mtime: 0, size },
    format,
    getAttachmentFileContent: () => Promise.resolve(byteLength === undefined ? undefined : new ArrayBuffer(byteLength))
  });
}

describe('AttachmentFileSizeToken', () => {
  it('should be named attachmentFileSize', () => {
    const token = new AttachmentFileSizeToken();
    expect(token.name).toBe('attachmentFileSize');
  });

  it('should report 0 bytes when there is no attachment content', async () => {
    const token = new AttachmentFileSizeToken();
    const result = await token.evaluate(createContext(undefined, null));
    expect(result).toBe('0');
  });

  it('should report bytes by default', async () => {
    const token = new AttachmentFileSizeToken();
    const result = await token.evaluate(createContext(2048, null));
    expect(result).toBe('2048');
  });

  it('should report kilobytes with decimal points', async () => {
    const token = new AttachmentFileSizeToken();
    const result = await token.evaluate(createContext(2048, { decimalPoints: 2, unit: 'KB' }));
    expect(result).toBe('2.00');
  });

  it('should report megabytes with decimal points', async () => {
    const token = new AttachmentFileSizeToken();
    const result = await token.evaluate(createContext(1024 * 1024 * 3, { decimalPoints: 1, unit: 'MB' }));
    expect(result).toBe('3.0');
  });

  it('should report the file stats size without reading content', async () => {
    const token = new AttachmentFileSizeToken();
    const getAttachmentFileContent = vi.fn<() => Promise<ArrayBuffer | undefined>>();
    const result = await token.evaluate(castTo<TokenEvaluatorContext>({
      attachmentFileStats: { ctime: 0, mtime: 0, size: 4096 },
      format: null,
      getAttachmentFileContent
    }));
    expect(result).toBe('4096');
    expect(getAttachmentFileContent).not.toHaveBeenCalled();
  });

  it('should prefer the file stats size over the content byte length', async () => {
    const token = new AttachmentFileSizeToken();
    const result = await token.evaluate(createStatsContext(4096, 1, null));
    expect(result).toBe('4096');
  });

  it('should reject an invalid unit through the schema', () => {
    const token = new AttachmentFileSizeToken();
    const format = castTo<TokenEvaluatorContext['format']>({ decimalPoints: 0, unit: 'GB' });
    expect(() => token.evaluate(createContext(1024, format))).toThrow();
  });

  it('should throw on an invalid unit reaching the evaluator directly', async () => {
    const token = new TestableAttachmentFileSizeToken();
    const format = castTo<EvaluateImplFormat>({ decimalPoints: 0, unit: 'GB' });
    await expect(token.callEvaluateImpl(createContext(1024, null), format)).rejects.toThrow('Invalid file size unit: GB');
  });
});
