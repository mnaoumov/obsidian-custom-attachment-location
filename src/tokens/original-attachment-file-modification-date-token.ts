import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  formatDate,
  formatNow,
  momentJsFormatSchema
} from './moment-js-token-base.ts';
import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({
  ...momentJsFormatSchema.shape,
  valueWhenUnknown: z.enum(['empty', 'now']).optional().default('empty')
});
type Format = z.infer<typeof formatSchema>;

export class OriginalAttachmentFileModificationDateToken extends TokenBase<Format> {
  public constructor() {
    super('originalAttachmentFileModificationDate', formatSchema);
  }

  protected override evaluateImpl(context: TokenEvaluatorContext, format: Format): string {
    if (context.attachmentFileStats?.mtime !== undefined) {
      return formatDate(context.attachmentFileStats.mtime, format);
    }

    if (format.valueWhenUnknown === 'now') {
      return formatNow(format);
    }

    return '';
  }
}
