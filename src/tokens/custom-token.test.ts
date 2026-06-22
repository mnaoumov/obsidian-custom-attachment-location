import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';
import type { TokenEvaluator } from './custom-token.ts';

import { CustomToken } from './custom-token.ts';

function createContext(format: TokenEvaluatorContext['format']): TokenEvaluatorContext {
  return strictProxy<TokenEvaluatorContext>({
    format
  });
}

describe('CustomToken', () => {
  it('should use the provided name', () => {
    const evaluator = vi.fn<TokenEvaluator>();
    const token = new CustomToken('myToken', evaluator);
    expect(token.name).toBe('myToken');
  });

  it('should delegate evaluation to the evaluator', async () => {
    const evaluator = vi.fn<TokenEvaluator>(() => 'evaluated');
    const token = new CustomToken('myToken', evaluator);
    const ctx = createContext({ extra: true });
    const result = await token.evaluate(ctx);
    expect(result).toBe('evaluated');
    expect(evaluator).toHaveBeenCalledWith(ctx);
  });

  it('should accept any loose format object', async () => {
    const evaluator = vi.fn<TokenEvaluator>(() => 'ok');
    const token = new CustomToken('myToken', evaluator);
    const result = await token.evaluate(createContext({ anything: 'goes', nested: { value: 1 } }));
    expect(result).toBe('ok');
  });
});
