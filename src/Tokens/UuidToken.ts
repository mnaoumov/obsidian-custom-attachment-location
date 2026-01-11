import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({
  case: z.enum(['lower', 'upper']).optional().default('lower'),
  hyphens: z.boolean().optional().default(true)
});
type Format = z.infer<typeof formatSchema>;

export class UuidToken extends TokenBase<Format> {
  public constructor() {
    super('uuid', formatSchema);
  }

  protected override evaluateImpl(_ctx: TokenEvaluatorContext, format: Format): string {
    let uuid = crypto.randomUUID() as string;
    if (format.case === 'upper') {
      uuid = uuid.toUpperCase();
    }
    return format.hyphens ? uuid : uuid.replace(/-/g, '');
  }
}
