import {
  describe,
  expect,
  it
} from 'vitest';

import { getRangeStr } from './get-range-str.ts';

describe('getRangeStr', () => {
  it('should build an inclusive character range', () => {
    expect(getRangeStr({ from: 'a', to: 'e' })).toBe('abcde');
  });

  it('should throw when the from value is not a single character', () => {
    expect(() => getRangeStr({ from: 'ab', to: 'z' })).toThrow('Range must be from-to a single character: ab to z');
  });

  it('should throw when the to value is not a single character', () => {
    expect(() => getRangeStr({ from: 'a', to: 'yz' })).toThrow('Range must be from-to a single character: a to yz');
  });
});
