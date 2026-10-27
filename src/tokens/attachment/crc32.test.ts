import { bytesToHex } from '@noble/hashes/utils.js';
import {
  describe,
  expect,
  it
} from 'vitest';

import { crc32 } from './crc32.ts';

function crc32Hex(content: string): string {
  return bytesToHex(crc32(new TextEncoder().encode(content)));
}

describe('crc32', () => {
  it('should match the IEEE CRC-32 of "hello"', () => {
    expect(crc32Hex('hello')).toBe('3610a686');
  });

  it('should match the standard check value of "123456789"', () => {
    expect(crc32Hex('123456789')).toBe('cbf43926');
  });

  it('should be zero for empty content', () => {
    expect(crc32Hex('')).toBe('00000000');
  });

  it('should print its bytes in big-endian order', () => {
    expect(crc32Hex('a')).toBe('e8b7be43');
    expect(crc32Hex('The quick brown fox jumps over the lazy dog')).toBe('414fa339');
  });
});
