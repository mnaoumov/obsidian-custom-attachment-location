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
 * The creation date of the attachment file itself. Renaming a file does not change it, so it has no separate original.
 */
export class AttachmentFileCreationDateToken extends TokenBase<Format> {
  public constructor(name = 'attachmentFileCreationDate') {
    super(name, formatSchema);
  }

  protected override evaluateImpl(context: TokenEvaluatorContext, format: Format): string {
    if (context.attachmentFileStats?.ctime !== undefined) {
      return formatDate(context.attachmentFileStats.ctime, format);
    }

    return format.valueWhenUnknown === 'now' ? formatNow(format) : '';
  }
}
