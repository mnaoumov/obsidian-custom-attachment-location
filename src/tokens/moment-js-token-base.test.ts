import { moment as moment_ } from 'obsidian';
import { extractDefaultExportInterop } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';
import { z } from 'zod';

import {
  formatDate,
  formatNow,
  momentJsFormatSchema,
  withMomentJsFormatShorthand
} from './moment-js-token-base.ts';

const moment = extractDefaultExportInterop(moment_);

const UNIX_TIMESTAMP_IN_MILLISECONDS = Date.UTC(2021, 4, 17, 12, 34, 56);

describe('momentJsFormatSchema', () => {
  it('should parse a momentJsFormat string', () => {
    const result = momentJsFormatSchema.parse({ momentJsFormat: 'YYYY-MM-DD' });
    expect(result).toStrictEqual({ momentJsFormat: 'YYYY-MM-DD' });
  });

  it('should reject a missing momentJsFormat', () => {
    expect(() => momentJsFormatSchema.parse({})).toThrow();
  });
});

describe('withMomentJsFormatShorthand', () => {
  const schema = withMomentJsFormatShorthand(z.strictObject({
    ...momentJsFormatSchema.shape,
    valueWhenUnknown: z.enum(['empty', 'now']).optional().default('empty')
  }));

  it('should take a bare string as the moment.js format, keeping the other defaults', () => {
    expect(schema.parse('YYYY-MM-DD')).toStrictEqual({ momentJsFormat: 'YYYY-MM-DD', valueWhenUnknown: 'empty' });
  });

  it('should still take the object form', () => {
    expect(schema.parse({ momentJsFormat: 'YYYY', valueWhenUnknown: 'now' })).toStrictEqual({ momentJsFormat: 'YYYY', valueWhenUnknown: 'now' });
  });

  it('should still reject a missing moment.js format', () => {
    expect(() => schema.parse({})).toThrow();
  });
});

describe('formatDate', () => {
  it('should format a unix timestamp according to the format', () => {
    const expected = moment(UNIX_TIMESTAMP_IN_MILLISECONDS).format('YYYY-MM-DD');
    expect(formatDate(UNIX_TIMESTAMP_IN_MILLISECONDS, { momentJsFormat: 'YYYY-MM-DD' })).toBe(expected);
  });
});

describe('formatNow', () => {
  it('should format the current time according to the format', () => {
    expect(formatNow({ momentJsFormat: '[constant]' })).toBe('constant');
  });
});
