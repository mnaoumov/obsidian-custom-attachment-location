import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({
  decimalPoints: z.int().nonnegative().optional().default(0),
  unit: z.enum(['B', 'KB', 'MB']).optional().default('B')
});
type Format = z.infer<typeof formatSchema>;

export class AttachmentFileSizeToken extends TokenBase<Format> {
  public constructor() {
    super('attachmentFileSize', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    const sizeInBytes = ctx.attachmentFileContent?.byteLength ?? 0;
    const BYTES_IN_KB = 1024;
    const BYTES_IN_MB = BYTES_IN_KB * BYTES_IN_KB;

    switch (format.unit) {
      case 'B':
        return sizeInBytes.toFixed(format.decimalPoints);
      case 'KB':
        return (sizeInBytes / BYTES_IN_KB).toFixed(format.decimalPoints);
      case 'MB':
        return (sizeInBytes / BYTES_IN_MB).toFixed(format.decimalPoints);
      default:
        throw new Error(`Invalid file size unit: ${format.unit as string}`);
    }
  }
}
