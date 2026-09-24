import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  formatDate,
  formatNow,
  momentJsFormatSchema,
  withMomentJsFormatShorthand
} from './moment-js-token-base.ts';
import { TokenBase } from './token-base.ts';

const formatSchema = withMomentJsFormatShorthand(z.strictObject({
  ...momentJsFormatSchema.shape,
  valueWhenUnknown: z.enum(['empty', 'now']).optional().default('empty')
}));
type Format = z.output<typeof formatSchema>;

export class OriginalAttachmentFileCreationDateToken extends TokenBase<Format> {
  public constructor() {
    super('originalAttachmentFileCreationDate', formatSchema);
  }

  protected override evaluateImpl(context: TokenEvaluatorContext, format: Format): string {
    if (context.attachmentFileStats?.ctime !== undefined) {
      return formatDate(context.attachmentFileStats.ctime, format);
    }

    return format.valueWhenUnknown === 'now' ? formatNow(format) : '';
  }
}
