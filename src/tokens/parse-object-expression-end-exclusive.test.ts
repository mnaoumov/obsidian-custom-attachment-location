import {
  describe,
  expect,
  it
} from 'vitest';

import { parseObjectExpressionEndExclusive } from './parse-object-expression-end-exclusive.ts';

describe('parseObjectExpressionEndExclusive', () => {
  it('should return the end offset of an object expression', () => {
    expect(parseObjectExpressionEndExclusive({
      objectStart: 0,
      string: '{ a: 1 }',
      throwOnError: true,
      tokenName: 'token'
    })).toBe(8);
  });

  it('should throw when the expression is not an object literal and throwOnError is true', () => {
    expect(() =>
      parseObjectExpressionEndExclusive({
        objectStart: 0,
        string: '123',
        throwOnError: true,
        tokenName: 'token'
      })
    ).toThrow('Invalid JSON5 object for token \'token\'');
  });

  it('should return null when the expression is not an object literal and throwOnError is false', () => {
    expect(parseObjectExpressionEndExclusive({
      objectStart: 0,
      string: '123',
      throwOnError: false,
      tokenName: 'token'
    })).toBeNull();
  });
});
