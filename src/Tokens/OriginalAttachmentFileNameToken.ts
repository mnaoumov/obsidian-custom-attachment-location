import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import {
  formatString,
  stringFormatSchema
} from './StringTokenBase.ts';
import { TokenBase } from './TokenBase.ts';

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
