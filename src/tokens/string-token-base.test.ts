import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import {
  formatString,
  stringFormatSchema
} from './string-token-base.ts';

type StringFormat = Parameters<typeof formatString>[1];

describe('stringFormatSchema', () => {
  it('should accept an empty object', () => {
    const result = stringFormatSchema.parse({});
    expect(result).toStrictEqual({});
  });

  it('should reject unknown keys', () => {
    expect(() => stringFormatSchema.parse({ unknown: true })).toThrow();
  });

  it('should reject a non-positive trim length', () => {
    expect(() => stringFormatSchema.parse({ trim: { length: 0, side: 'left' } })).toThrow();
  });
});

describe('formatString', () => {
  it('should return the value unchanged when format is empty', () => {
    expect(formatString('Hello', {})).toBe('Hello');
  });

  it('should trim from the left', () => {
    expect(formatString('Hello', { trim: { length: 3, side: 'left' } })).toBe('Hel');
  });

  it('should trim from the right', () => {
    expect(formatString('Hello', { trim: { length: 3, side: 'right' } })).toBe('llo');
  });

  it('should slugify the value', () => {
    expect(formatString('Hello World', { slugify: true })).toBe('Hello-World');
  });

  it('should lowercase the value', () => {
    expect(formatString('Hello', { case: 'lower' })).toBe('hello');
  });

  it('should uppercase the value', () => {
    expect(formatString('Hello', { case: 'upper' })).toBe('HELLO');
  });

  it('should combine trim, slugify, and case', () => {
    expect(formatString('Hello World', { case: 'upper', slugify: true, trim: { length: 5, side: 'left' } })).toBe('HELLO');
  });

  it('should throw on an invalid trim side', () => {
    const format = castTo<StringFormat>({ trim: { length: 3, side: 'invalid' } });
    expect(() => formatString('Hello', format)).toThrow('Invalid trim side: invalid');
  });

  it('should throw on an invalid case', () => {
    const format = castTo<StringFormat>({ case: 'invalid' });
    expect(() => formatString('Hello', format)).toThrow('Invalid case: invalid');
  });
});
