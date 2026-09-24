/* eslint-disable no-template-curly-in-string -- The retired `${...}` plugin token syntax is under test, not JS template literals. */
import {
  describe,
  expect,
  it
} from 'vitest';

import {
  findLegacyToken,
  LegacyTokenSyntaxError,
  migrateLegacyTokenSyntax,
  parseFormatObject,
  parseTokenFormat,
  scanTokens,
  TokenSyntax
} from './token-parser.ts';

describe('parseFormatObject', () => {
  it('should parse a JSON5 object', () => {
    expect(parseFormatObject({
      formatText: '{ a: 1, b: "x" }',
      tokenName: 'token'
    })).toStrictEqual({ a: 1, b: 'x' });
  });

  it('should throw on invalid JSON5', () => {
    expect(() =>
      parseFormatObject({
        formatText: '{ a: }',
        tokenName: 'token'
      })
    ).toThrow('Invalid JSON5');
  });

  it('should throw when the parsed value is null', () => {
    expect(() =>
      parseFormatObject({
        formatText: 'null',
        tokenName: 'token'
      })
    ).toThrow('Format for token \'token\' must be a JSON5 object');
  });

  it('should throw when the parsed value is not an object', () => {
    expect(() =>
      parseFormatObject({
        formatText: '42',
        tokenName: 'token'
      })
    ).toThrow('Format for token \'token\' must be a JSON5 object');
  });

  it('should throw when the parsed value is an array', () => {
    expect(() =>
      parseFormatObject({
        formatText: '[1, 2]',
        tokenName: 'token'
      })
    ).toThrow('Format for token \'token\' must be a JSON5 object');
  });
});

describe('parseTokenFormat', () => {
  it('should return null for a token without a format', () => {
    expect(parseTokenFormat({ formatText: null, isScalarFormat: false, token: 'date' })).toBeNull();
  });

  it('should return a scalar format as it is', () => {
    expect(parseTokenFormat({ formatText: 'YYYY-MM-DD', isScalarFormat: true, token: 'date' })).toBe('YYYY-MM-DD');
  });

  it('should parse an object format', () => {
    expect(parseTokenFormat({ formatText: '{ a: 1 }', isScalarFormat: false, token: 'date' })).toStrictEqual({ a: 1 });
  });
});

describe('scanTokens', () => {
  it('should return an empty array when there are no tokens', () => {
    expect(scanTokens('no tokens here')).toStrictEqual([]);
  });

  it('should scan a token without a format', () => {
    const result = scanTokens('{{date}}');
    expect(result).toStrictEqual([{
      end: 8,
      formatText: null,
      isScalarFormat: false,
      raw: '{{date}}',
      start: 0,
      token: 'date'
    }]);
  });

  it('should scan a token with surrounding whitespace and a colon-less close', () => {
    const result = scanTokens('{{  date  }}');
    expect(result[0]?.token).toBe('date');
    expect(result[0]?.formatText).toBeNull();
  });

  it('should scan a token with a JSON5 object format', () => {
    const result = scanTokens('{{date: { momentJsFormat: "YYYY" }}}');
    expect(result[0]?.token).toBe('date');
    expect(result[0]?.formatText).toBe('{ momentJsFormat: "YYYY" }');
    expect(result[0]?.isScalarFormat).toBe(false);
    expect(result[0]?.raw).toBe('{{date: { momentJsFormat: "YYYY" }}}');
  });

  it('should find the end of a nested format object without guessing at the brace run', () => {
    const result = scanTokens('a{{x:{b:{c:1}}}}z');
    expect(result[0]?.formatText).toBe('{b:{c:1}}');
    expect(result[0]?.end).toBe(16);
  });

  it('should scan the scalar format shorthand', () => {
    const result = scanTokens('file-{{date:YYYY-MM-DD}}.png');
    expect(result).toStrictEqual([{
      end: 24,
      formatText: 'YYYY-MM-DD',
      isScalarFormat: true,
      raw: '{{date:YYYY-MM-DD}}',
      start: 5,
      token: 'date'
    }]);
  });

  it('should trim the whitespace around a scalar format', () => {
    expect(scanTokens('{{date: HH:mm }}')[0]?.formatText).toBe('HH:mm');
  });

  it('should scan multiple tokens', () => {
    const result = scanTokens('{{a}}-{{b}}');
    expect(result.map((t) => t.token)).toStrictEqual(['a', 'b']);
  });

  it('should not scan a template nested in a format object as a token of its own', () => {
    const result = scanTokens('{{prompt:{defaultValueTemplate:\'{{originalAttachmentFileName}}\'}}}');
    expect(result.map((t) => t.token)).toStrictEqual(['prompt']);
    expect(result[0]?.formatText).toBe('{defaultValueTemplate:\'{{originalAttachmentFileName}}\'}');
  });

  it('should take the innermost {{ of a longer brace run as the token start', () => {
    const result = scanTokens('{{{a}}}');
    expect(result.map((t) => t.raw)).toStrictEqual(['{{a}}']);
  });

  it('should throw on an invalid token start', () => {
    expect(() => scanTokens('{{!')).toThrow('Invalid token start');
  });

  it('should throw on a whitespace-only token name', () => {
    expect(() => scanTokens('{{ }}')).toThrow('Invalid token start');
  });

  it('should throw when a colon-less token is missing its closing braces', () => {
    expect(() => scanTokens('{{date')).toThrow('Token \'date\' is missing closing \'}}\'');
  });

  it('should throw when a colon-less token has only one closing brace', () => {
    expect(() => scanTokens('{{date}')).toThrow('Token \'date\' is missing closing \'}}\'');
  });

  it('should throw when a colon-less token has unexpected trailing content', () => {
    expect(() => scanTokens('{{date x}}')).toThrow('Token \'date\' is missing closing \'}}\'');
  });

  it('should throw when a scalar format is never closed', () => {
    expect(() => scanTokens('{{date:YYYY')).toThrow('Token \'date\' is missing closing \'}}\'');
  });

  it('should throw on an empty scalar format', () => {
    expect(() => scanTokens('{{date: }}')).toThrow('Token \'date\' has an empty format');
  });

  it('should throw on a scalar format holding a brace', () => {
    expect(() => scanTokens('{{date:YY}YY}}')).toThrow('Token \'date\' scalar format must not contain \'{\' or \'}\'');
  });

  it('should throw when the format object is invalid', () => {
    expect(() => scanTokens('{{date: {')).toThrow('Invalid JSON5 object for token \'date\'');
  });

  it('should throw when the format object is missing its closing braces', () => {
    expect(() => scanTokens('{{date: {} x')).toThrow('Token \'date\' is missing closing \'}}\'');
  });

  it('should throw when the format object is followed by only one closing brace', () => {
    expect(() => scanTokens('{{date: {}}')).toThrow('Token \'date\' is missing closing \'}}\'');
  });

  it('should throw a LegacyTokenSyntaxError on a token in the retired syntax', () => {
    expect(() => scanTokens('./assets/${noteFileName}')).toThrow(LegacyTokenSyntaxError);
  });

  it('should skip invalid tokens when throwOnError is false', () => {
    const result = scanTokens('{{date}} {{ }} {{bad', { throwOnError: false });
    expect(result.map((t) => t.token)).toStrictEqual(['date']);
  });

  it('should ignore a token in the retired syntax when throwOnError is false', () => {
    expect(scanTokens('${date} {{a}}', { throwOnError: false }).map((t) => t.token)).toStrictEqual(['a']);
  });

  it('should skip a colon-less token missing its closing braces when throwOnError is false', () => {
    expect(scanTokens('{{date', { throwOnError: false })).toStrictEqual([]);
  });

  it('should skip an unclosed scalar format when throwOnError is false', () => {
    expect(scanTokens('{{date:YYYY', { throwOnError: false })).toStrictEqual([]);
  });

  it('should skip an empty scalar format when throwOnError is false', () => {
    expect(scanTokens('{{date: }}', { throwOnError: false })).toStrictEqual([]);
  });

  it('should skip a token with an invalid format object when throwOnError is false', () => {
    expect(scanTokens('{{date: {', { throwOnError: false })).toStrictEqual([]);
  });

  it('should skip a token whose format object is missing its closing braces when throwOnError is false', () => {
    expect(scanTokens('{{date: {} x', { throwOnError: false })).toStrictEqual([]);
  });

  it('should skip an invalid token start when throwOnError is false', () => {
    expect(scanTokens('{{!', { throwOnError: false })).toStrictEqual([]);
  });

  describe('legacy syntax', () => {
    it('should scan a legacy token', () => {
      expect(scanTokens('${date}', { syntax: TokenSyntax.Legacy })).toStrictEqual([{
        end: 7,
        formatText: null,
        isScalarFormat: false,
        raw: '${date}',
        start: 0,
        token: 'date'
      }]);
    });

    it('should scan a legacy token with a JSON5 object format', () => {
      expect(scanTokens('${date:{momentJsFormat:"YYYY"}}', { syntax: TokenSyntax.Legacy })[0]?.formatText).toBe('{momentJsFormat:"YYYY"}');
    });

    it('should not accept a scalar format', () => {
      expect(() => scanTokens('${date: "x"}', { syntax: TokenSyntax.Legacy })).toThrow(
        'Token \'date\' format must be a JSON5 object starting with \'{\''
      );
    });

    it('should skip a scalar format when throwOnError is false', () => {
      expect(scanTokens('${date: "x"}', { syntax: TokenSyntax.Legacy, throwOnError: false })).toStrictEqual([]);
    });

    it('should throw when a legacy token is missing its closing brace', () => {
      expect(() => scanTokens('${date', { syntax: TokenSyntax.Legacy })).toThrow('Token \'date\' is missing closing \'}\'');
    });
  });
});

describe('findLegacyToken', () => {
  it('should return null when there is no legacy token', () => {
    expect(findLegacyToken('./assets/{{noteFileName}}')).toBeNull();
  });

  it('should not take a lone dollar-brace for a token', () => {
    expect(findLegacyToken('price ${ 5')).toBeNull();
  });

  it('should name the legacy token and its replacement', () => {
    const error = findLegacyToken('./assets/${noteFileName}');
    expect(error?.legacyToken).toBe('${noteFileName}');
    expect(error?.replacement).toBe('{{noteFileName}}');
    expect(error?.message).toBe(
      'The token \'${noteFileName}\' uses the \'${...}\' syntax, which is no longer supported. Write it as \'{{noteFileName}}\' instead.'
    );
  });

  it('should carry a format object into the replacement', () => {
    expect(findLegacyToken('file-${date:{momentJsFormat:\'YYYY\'}}')?.replacement).toBe('{{date:{momentJsFormat:\'YYYY\'}}}');
  });

  it('should still name a legacy token that does not parse', () => {
    const error = findLegacyToken('${date:YYYY}');
    expect(error?.legacyToken).toBe('${date');
    expect(error?.replacement).toBe('{{date}}');
  });
});

describe('migrateLegacyTokenSyntax', () => {
  it.each([
    ['./assets/${noteFileName}', './assets/{{noteFileName}}'],
    ['${ noteFileName }', '{{noteFileName}}'],
    ['file-${date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}', 'file-{{date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}}'],
    ['${a}-${b:{c:1}}', '{{a}}-{{b:{c:1}}}'],
    [
      '${prompt:{defaultValueTemplate:\'${originalAttachmentFileName}-${date:{momentJsFormat:"YYYY"}}\'}}',
      '{{prompt:{defaultValueTemplate:\'{{originalAttachmentFileName}}-{{date:{momentJsFormat:"YYYY"}}}\'}}}'
    ],
    ['no tokens', 'no tokens'],
    ['', ''],
    ['already {{migrated}}', 'already {{migrated}}'],
    ['broken ${date', 'broken ${date']
  ])('should migrate %j to %j', (legacy, migrated) => {
    expect(migrateLegacyTokenSyntax(legacy)).toBe(migrated);
  });

  it('should produce a template the parser reads back as the same tokens', () => {
    const legacy = 'x-${date:{momentJsFormat:\'YYYY\'}}-${noteFileName}';
    const legacyTokens = scanTokens(legacy, { syntax: TokenSyntax.Legacy });
    const migratedTokens = scanTokens(migrateLegacyTokenSyntax(legacy));
    expect(migratedTokens.map((t) => [t.token, t.formatText])).toStrictEqual(legacyTokens.map((t) => [t.token, t.formatText]));
  });

  it('should be idempotent', () => {
    const once = migrateLegacyTokenSyntax('${a}/${b:{c:1}}');
    expect(migrateLegacyTokenSyntax(once)).toBe(once);
  });
});
/* eslint-enable no-template-curly-in-string -- The retired `${...}` plugin token syntax is under test, not JS template literals. */
