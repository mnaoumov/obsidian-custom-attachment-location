import {
  describe,
  expect,
  it
} from 'vitest';

import { getRangeString } from './get-range-string.ts';

describe('getRangeString', () => {
  it('should build an inclusive character range', () => {
    expect(getRangeString({ from: 'a', to: 'e' })).toBe('abcde');
  });

  it('should throw when the from value is not a single character', () => {
    expect(() => getRangeString({ from: 'ab', to: 'z' })).toThrow('Range must be from-to a single character: ab to z');
  });

  it('should throw when the to value is not a single character', () => {
    expect(() => getRangeString({ from: 'a', to: 'yz' })).toThrow('Range must be from-to a single character: a to yz');
  });
});
