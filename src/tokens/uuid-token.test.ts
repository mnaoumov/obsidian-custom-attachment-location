import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { UuidToken } from './uuid-token.ts';

const UUID_WITH_HYPHENS_REG_EXP = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const UUID_WITHOUT_HYPHENS_REG_EXP = /^[0-9a-f]{32}$/;
const UUID_UPPER_WITH_HYPHENS_REG_EXP = /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/;

function createContext(format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format
  });
}

describe('UuidToken', () => {
  it('should be named uuid', () => {
    const token = new UuidToken();
    expect(token.name).toBe('uuid');
  });

  it('should generate a lowercase hyphenated uuid by default', () => {
    const token = new UuidToken();
    const result = token.evaluate(createContext(null));
    expect(result).toMatch(UUID_WITH_HYPHENS_REG_EXP);
  });

  it('should generate an uppercase uuid', () => {
    const token = new UuidToken();
    const result = token.evaluate(createContext({ case: 'upper' }));
    expect(result).toMatch(UUID_UPPER_WITH_HYPHENS_REG_EXP);
  });

  it('should generate a uuid without hyphens', () => {
    const token = new UuidToken();
    const result = token.evaluate(createContext({ hyphens: false }));
    expect(result).toMatch(UUID_WITHOUT_HYPHENS_REG_EXP);
  });
});
