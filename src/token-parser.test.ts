import {
  describe,
  expect,
  it
} from 'vitest';

import {
  parseFormatObject,
  parseObjectExpressionEndExclusive,
  scanTokens
} from './token-parser.ts';

describe('parseFormatObject', () => {
  it('should parse a JSON5 object', () => {
    expect(parseFormatObject('{ a: 1, b: "x" }', 'token')).toStrictEqual({ a: 1, b: 'x' });
  });

  it('should throw on invalid JSON5', () => {
    expect(() => parseFormatObject('{ a: }', 'token')).toThrow('Invalid JSON5');
  });

  it('should throw when the parsed value is null', () => {
    expect(() => parseFormatObject('null', 'token')).toThrow('Format for token \'token\' must be a JSON5 object');
  });

  it('should throw when the parsed value is not an object', () => {
    expect(() => parseFormatObject('42', 'token')).toThrow('Format for token \'token\' must be a JSON5 object');
  });

  it('should throw when the parsed value is an array', () => {
    expect(() => parseFormatObject('[1, 2]', 'token')).toThrow('Format for token \'token\' must be a JSON5 object');
  });
});

describe('parseObjectExpressionEndExclusive', () => {
  it('should return the end offset of an object expression', () => {
    expect(parseObjectExpressionEndExclusive('{ a: 1 }', 0, 'token', true)).toBe(8);
  });

  it('should throw when the expression is not an object literal and throwOnError is true', () => {
    expect(() => parseObjectExpressionEndExclusive('123', 0, 'token', true)).toThrow('Invalid JSON5 object for token \'token\'');
  });

  it('should return null when the expression is not an object literal and throwOnError is false', () => {
    expect(parseObjectExpressionEndExclusive('123', 0, 'token', false)).toBeNull();
  });
});

describe('scanTokens', () => {
  it('should return an empty array when there are no tokens', () => {
    expect(scanTokens('no tokens here')).toStrictEqual([]);
  });

  it('should scan a token without a format', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    const result = scanTokens('${date}');
    expect(result).toStrictEqual([{
      end: 7,
      formatText: null,
      // eslint-disable-next-line no-template-curly-in-string -- Token under test.
      raw: '${date}',
      start: 0,
      token: 'date'
    }]);
  });

  it('should scan a token with surrounding whitespace and a colon-less close', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    const result = scanTokens('${  date  }');
    expect(result[0]?.token).toBe('date');
    expect(result[0]?.formatText).toBeNull();
  });

  it('should scan a token with a JSON5 object format', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    const result = scanTokens('${date: { momentJsFormat: "YYYY" }}');
    expect(result[0]?.token).toBe('date');
    expect(result[0]?.formatText).toBe('{ momentJsFormat: "YYYY" }');
  });

  it('should scan multiple tokens', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Tokens under test.
    const result = scanTokens('${a}-${b}');
    expect(result.map((t) => t.token)).toStrictEqual(['a', 'b']);
  });

  it('should throw on an invalid token start', () => {
    expect(() => scanTokens('${!')).toThrow('Invalid token start');
  });

  it('should throw on a whitespace-only token name', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    expect(() => scanTokens('${ }')).toThrow('Invalid token start');
  });

  it('should throw when a colon-less token is missing its closing brace', () => {
    expect(() => scanTokens('${date')).toThrow('Token \'date\' is missing closing \'}\'');
  });

  it('should throw when a colon-less token has unexpected trailing content', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    expect(() => scanTokens('${date x}')).toThrow('Token \'date\' is missing closing \'}\'');
  });

  it('should throw when a format does not start with an object brace', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    expect(() => scanTokens('${date: "x"}')).toThrow('Token \'date\' format must be a JSON5 object starting with \'{\'');
  });

  it('should throw when the format object is invalid', () => {
    expect(() => scanTokens('${date: {')).toThrow('Invalid JSON5 object for token \'date\'');
  });

  it('should throw when the format expression is not an object literal', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    expect(() => scanTokens('${date: 123}')).toThrow('Token \'date\' format must be a JSON5 object starting with \'{\'');
  });

  it('should throw when the format object is missing its closing brace', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    expect(() => scanTokens('${date: {} x')).toThrow('Token \'date\' is missing closing \'}\'');
  });

  it('should skip invalid tokens when throwOnError is false', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Tokens under test.
    const result = scanTokens('${date} ${ } ${bad', { throwOnError: false });
    expect(result.map((t) => t.token)).toStrictEqual(['date']);
  });

  it('should skip a colon-less token missing its closing brace when throwOnError is false', () => {
    const result = scanTokens('${date', { throwOnError: false });
    expect(result).toStrictEqual([]);
  });

  it('should skip a token whose format does not start with a brace when throwOnError is false', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    const result = scanTokens('${date: "x"}', { throwOnError: false });
    expect(result).toStrictEqual([]);
  });

  it('should skip a token with an invalid format object when throwOnError is false', () => {
    const result = scanTokens('${date: {', { throwOnError: false });
    expect(result).toStrictEqual([]);
  });

  it('should skip a token with a non-object format expression when throwOnError is false', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    const result = scanTokens('${date: [1]}', { throwOnError: false });
    expect(result).toStrictEqual([]);
  });

  it('should skip a token whose format object is missing its closing brace when throwOnError is false', () => {
    // eslint-disable-next-line no-template-curly-in-string -- Token under test.
    const result = scanTokens('${date: {} x', { throwOnError: false });
    expect(result).toStrictEqual([]);
  });

  it('should skip an invalid token start when throwOnError is false', () => {
    const result = scanTokens('${!', { throwOnError: false });
    expect(result).toStrictEqual([]);
  });
});
