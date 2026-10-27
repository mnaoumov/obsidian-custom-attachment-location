import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  formatString,
  stringFormatSchema
} from '../base/string-token-base.ts';
import { TokenBase } from '../base/token-base.ts';

const formatSchema = z.strictObject({
  ...stringFormatSchema.shape
});
type Format = z.infer<typeof formatSchema>;

/**
 * The attachment's name as it is right now: the incoming file's when pasting, the file's current one otherwise.
 *
 * `{{originalAttachmentFileName}}` is the name it arrived with instead.
 */
export class AttachmentFileNameToken extends TokenBase<Format> {
  public constructor() {
    super('attachmentFileName', formatSchema);
  }

  protected override evaluateImpl(context: TokenEvaluatorContext, format: Format): string {
    return formatString(context.attachmentFileName, format);
  }
}
