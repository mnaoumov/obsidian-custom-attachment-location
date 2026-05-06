import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  formatString,
  stringFormatSchema
} from './string-token-base.ts';
import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({
  ...stringFormatSchema.shape
});
type Format = z.infer<typeof formatSchema>;

export class OriginalAttachmentFileNameToken extends TokenBase<Format> {
  public constructor() {
    super('originalAttachmentFileName', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    return formatString(ctx.originalAttachmentFileName, format);
  }
}
