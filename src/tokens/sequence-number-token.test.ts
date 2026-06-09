import { castTo } from 'obsidian-dev-utils/object-utils';
import {
  describe,
  expect,
  it
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { SequenceNumberToken } from './sequence-number-token.ts';

function createContext(sequenceNumber: number, format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    format,
    sequenceNumber
  });
}

describe('SequenceNumberToken', () => {
  it('should be named sequenceNumber', () => {
    const token = new SequenceNumberToken();
    expect(token.name).toBe('sequenceNumber');
  });

  it('should output the sequence number without padding by default', () => {
    const token = new SequenceNumberToken();
    const result = token.evaluate(createContext(5, null));
    expect(result).toBe('5');
  });

  it('should pad the sequence number to the requested length', () => {
    const token = new SequenceNumberToken();
    const result = token.evaluate(createContext(5, { length: 3 }));
    expect(result).toBe('005');
  });
});
