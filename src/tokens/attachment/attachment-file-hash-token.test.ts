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
const EMPTY_BLAKE3 = 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262';

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

  it.each([
    ['CRC32', '3610a686'],
    ['MD5', '5d41402abc4b2a76b9719d911017c592'],
    ['SHA-1', HELLO_SHA_1],
    ['SHA-224', 'ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193'],
    ['SHA-256', HELLO_SHA_256],
    ['SHA-384', '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f'],
    [
      'SHA-512',
      '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043'
    ],
    ['SHA3-224', 'b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81'],
    ['SHA3-256', '3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392'],
    ['SHA3-384', '720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887'],
    [
      'SHA3-512',
      '75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976'
    ]
  ])('should hash "hello" with %s', async (algorithm, expected) => {
    const token = new AttachmentFileHashToken();
    expect(await token.evaluate(createContext('hello', { algorithm }))).toBe(expected);
  });

  it('should hash empty content with BLAKE3 to the official test vector', async () => {
    const token = new AttachmentFileHashToken();
    expect(await token.evaluate(createContext('', { algorithm: 'BLAKE3' }))).toBe(EMPTY_BLAKE3);
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
    expect(() => token.evaluate(createContext('hello', { algorithm: 'SHA-2' }))).toThrow();
  });

  it('should reject a non-positive length through the schema', () => {
    const token = new AttachmentFileHashToken();
    expect(() => token.evaluate(createContext('hello', { length: 0 }))).toThrow();
  });
});
