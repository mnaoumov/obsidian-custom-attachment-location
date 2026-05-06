import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({});
type Format = z.infer<typeof formatSchema>;

export class NoteFolderPathToken extends TokenBase<Format> {
  public constructor() {
    super('noteFolderPath', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext): string {
    return ctx.noteFolderPath;
  }
}
