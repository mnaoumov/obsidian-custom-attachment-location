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

export class GeneratedAttachmentFileNameToken extends TokenBase<Format> {
  public constructor() {
    super('generatedAttachmentFileName', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    return formatString(ctx.generatedAttachmentFileName, format);
  }
}
