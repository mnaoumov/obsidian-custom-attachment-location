import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({
  length: z.number().optional().default(1)
});
type Format = z.infer<typeof formatSchema>;

export class SequenceNumberToken extends TokenBase<Format> {
  public constructor() {
    super('sequenceNumber', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    return String(ctx.sequenceNumber).padStart(format.length, '0');
  }
}
