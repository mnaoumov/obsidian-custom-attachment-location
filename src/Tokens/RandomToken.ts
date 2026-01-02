import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import { TokenBase } from './TokenBase.ts';

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

  protected override evaluateImpl(_ctx: TokenEvaluatorContext, format: Format): string {
    let symbols = '';
    if (format.digits) {
      symbols += this.getRangeStr('0', '9');
    }
    if (format.letters) {
      switch (format.letterCase) {
        case 'lower':
          symbols += this.getRangeStr('a', 'z');
          break;
        case 'mixed':
          symbols += this.getRangeStr('a', 'z') + this.getRangeStr('A', 'Z');
          break;
        case 'upper':
          symbols += this.getRangeStr('A', 'Z');
          break;
        default:
          throw new Error(`Invalid letter case: ${format.letterCase as string}`);
      }
    }

    let ans = '';

    // eslint-disable-next-line @typescript-eslint/prefer-for-of -- Non-iterable.
    for (let i = 0; i < format.length; i++) {
      ans += symbols[Math.floor(Math.random() * symbols.length)] ?? '';
    }

    return ans;
  }

  private getRangeStr(from: string, to: string): string {
    if (from.length !== 1) {
      throw new Error(`Range must be from-to a single character: ${from} to ${to}`);
    }
    if (to.length !== 1) {
      throw new Error(`Range must be from-to a single character: ${from} to ${to}`);
    }

    let str = '';

    for (let i = from.charCodeAt(0); i <= to.charCodeAt(0); i++) {
      str += String.fromCharCode(i);
    }

    return str;
  }
}
