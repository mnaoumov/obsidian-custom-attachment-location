import { z } from 'zod';

import type { TokenEvaluator } from '../substitutions.ts';
import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from './token-base.ts';

const formatSchema = z.looseObject({});
type Format = z.infer<typeof formatSchema>;

export class CustomToken extends TokenBase<Format> {
  public constructor(name: string, private readonly evaluator: TokenEvaluator) {
    super(name, formatSchema);
  }

  protected override async evaluateImpl(ctx: TokenEvaluatorContext): Promise<string> {
    return this.evaluator(ctx);
  }
}
