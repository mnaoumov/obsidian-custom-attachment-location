import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from '../base/token-base.ts';

const formatSchema = z.strictObject({});
type Format = z.infer<typeof formatSchema>;

/**
 * The extension of the attachment as it is right now. `{{originalAttachmentFileExtension}}` is the one it arrived
 * with.
 */
export class AttachmentFileExtensionToken extends TokenBase<Format> {
  public constructor() {
    super('attachmentFileExtension', formatSchema);
  }

  protected override evaluateImpl(context: TokenEvaluatorContext): string {
    return context.attachmentFileExtension;
  }
}
