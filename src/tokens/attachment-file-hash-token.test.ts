import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { AttachmentFileHashToken } from './attachment-file-hash-token.ts';

const HELLO_SHA_256 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
const HELLO_SHA_1 = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d';
const EMPTY_SHA_256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function createContext(content: string | undefined, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format,
    getAttachmentFileContent: () => Promise.resolve(content === undefined ? undefined : new TextEncoder().encode(content).buffer)
  });
}

describe('AttachmentFileHashToken', () => {
  it('should be named attachmentFileHash', () => {
    const token = new AttachmentFileHashToken();
    expect(token.name).toBe('attachmentFileHash');
  });

  it('should produce the full lowercase SHA-256 by default', async () => {
    const token = new AttachmentFileHashToken();
    expect(await token.evaluate(createContext('hello', null))).toBe(HELLO_SHA_256);
  });

  it('should be stable under re-evaluation of unchanged content', async () => {
    const token = new AttachmentFileHashToken();
    const first = await token.evaluate(createContext('hello', null));
    const second = await token.evaluate(createContext('hello', null));
    expect(second).toBe(first);
  });

  it('should change when the content changes', async () => {
    const token = new AttachmentFileHashToken();
    expect(await token.evaluate(createContext('hello!', null))).not.toBe(HELLO_SHA_256);
  });

  it('should truncate to the requested length', async () => {
    const token = new AttachmentFileHashToken();
    expect(await token.evaluate(createContext('hello', { length: 12 }))).toBe(HELLO_SHA_256.slice(0, 12));
  });

  it('should use the requested algorithm', async () => {
    const token = new AttachmentFileHashToken();
    expect(await token.evaluate(createContext('hello', { algorithm: 'SHA-1' }))).toBe(HELLO_SHA_1);
  });

  it('should produce an uppercase hash', async () => {
    const token = new AttachmentFileHashToken();
    expect(await token.evaluate(createContext('hello', { case: 'upper', length: 8 }))).toBe(HELLO_SHA_256.slice(0, 8).toUpperCase());
  });

  it('should hash empty content when there is no attachment content', async () => {
    const token = new AttachmentFileHashToken();
    expect(await token.evaluate(createContext(undefined, null))).toBe(EMPTY_SHA_256);
  });

  it('should reject an unsupported algorithm through the schema', () => {
    const token = new AttachmentFileHashToken();
    expect(() => token.evaluate(createContext('hello', { algorithm: 'MD5' }))).toThrow();
  });

  it('should reject a non-positive length through the schema', () => {
    const token = new AttachmentFileHashToken();
    expect(() => token.evaluate(createContext('hello', { length: 0 }))).toThrow();
  });
});
