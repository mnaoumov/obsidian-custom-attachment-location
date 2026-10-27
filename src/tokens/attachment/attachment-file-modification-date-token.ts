import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  formatDate,
  formatNow,
  momentJsFormatSchema,
  withMomentJsFormatShorthand
} from '../base/moment-js-token-base.ts';
import { TokenBase } from '../base/token-base.ts';

const formatSchema = withMomentJsFormatShorthand(z.strictObject({
  ...momentJsFormatSchema.shape,
  valueWhenUnknown: z.enum(['empty', 'now']).optional().default('empty')
}));
type Format = z.output<typeof formatSchema>;

/**
 * The modification date of the attachment file itself. Renaming a file does not change it, so it has no separate original.
 */
export class AttachmentFileModificationDateToken extends TokenBase<Format> {
  public constructor(name = 'attachmentFileModificationDate') {
    super(name, formatSchema);
  }

  protected override evaluateImpl(context: TokenEvaluatorContext, format: Format): string {
    if (context.attachmentFileStats?.mtime !== undefined) {
      return formatDate(context.attachmentFileStats.mtime, format);
    }

    return format.valueWhenUnknown === 'now' ? formatNow(format) : '';
  }
}
