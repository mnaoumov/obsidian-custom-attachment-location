import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({});
type Format = z.infer<typeof formatSchema>;

export class OriginalAttachmentFileExtensionToken extends TokenBase<Format> {
  public constructor() {
    super('originalAttachmentFileExtension', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext): string {
    return ctx.originalAttachmentFileExtension;
  }
}
