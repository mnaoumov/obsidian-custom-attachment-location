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

export class OriginalAttachmentFileCreationDateToken extends TokenBase<Format> {
  public constructor() {
    super('originalAttachmentFileCreationDate', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    if (ctx.attachmentFileStat?.ctime !== undefined) {
      return formatDate(ctx.attachmentFileStat.ctime, format);
    }

    if (format.valueWhenUnknown === 'now') {
      return formatNow(format);
    }

    return '';
  }
}
