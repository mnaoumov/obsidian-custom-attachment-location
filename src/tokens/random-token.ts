import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { getRangeString } from './get-range-string.ts';
import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({
  digits: z.boolean().optional().default(true),
  length: z.number().optional().default(1),
  letterCase: z.enum(['lower', 'mixed', 'upper']).optional().default('upper'),
  letters: z.boolean().optional().default(true)
});
type Format = z.infer<typeof formatSchema>;

export class RandomToken extends TokenBase<Format> {
  public constructor() {
    super('random', formatSchema);
  }

  protected override evaluateImpl(_context: TokenEvaluatorContext, format: Format): string {
    let symbols = '';
    if (format.digits) {
      symbols += getRangeString({ from: '0', to: '9' });
    }
    if (format.letters) {
      switch (format.letterCase) {
        case 'lower': {
          symbols += getRangeString({ from: 'a', to: 'z' });
          break;
        }
        case 'mixed': {
          symbols += getRangeString({ from: 'a', to: 'z' }) + getRangeString({ from: 'A', to: 'Z' });
          break;
        }
        case 'upper': {
          symbols += getRangeString({ from: 'A', to: 'Z' });
          break;
        }
        default: {
          throw new Error(`Invalid letter case: ${format.letterCase as string}`);
        }
      }
    }

    let ans = '';

    // eslint-disable-next-line @typescript-eslint/prefer-for-of -- Non-iterable.
    for (let index = 0; index < format.length; index++) {
      ans += symbols[Math.floor(Math.random() * symbols.length)] ?? '';
    }

    return ans;
  }
}
