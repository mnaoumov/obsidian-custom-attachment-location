import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import {
  formatDate,
  formatNow,
  momentJsFormatSchema
} from './MomentJsTokenBase.ts';
import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({
  ...momentJsFormatSchema.shape,
  valueWhenUnknown: z.enum(['empty', 'now']).optional().default('empty')
});
type Format = z.infer<typeof formatSchema>;

export class OriginalAttachmentFileModificationDateToken extends TokenBase<Format> {
  public constructor() {
    super('originalAttachmentFileModificationDate', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    if (ctx.attachmentFileStat?.mtime !== undefined) {
      return formatDate(ctx.attachmentFileStat.mtime, format);
    }

    if (format.valueWhenUnknown === 'now') {
      return formatNow(format);
    }

    return '';
  }
}
