import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import {
  formatString,
  stringFormatSchema
} from './StringTokenBase.ts';
import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({
  ...stringFormatSchema.shape,
  pick: z.strictObject({
    from: z.enum(['start', 'end']),
    index: z.int().nonnegative().optional().default(0)
  }).optional()
});
type Format = z.infer<typeof formatSchema>;

export class NoteFolderNameToken extends TokenBase<Format> {
  public constructor() {
    super('noteFolderName', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    const folderParts = ctx.noteFolderPath.split('/');
    let folderPartIndex = folderParts.length - 1;
    switch (format.pick?.from) {
      case 'end':
        folderPartIndex = folderParts.length - 1 - format.pick.index;
        break;
      case 'start':
        folderPartIndex = format.pick.index;
        break;
      case undefined:
        break;
      default:
        throw new Error(`Invalid pick from: ${format.pick?.from as string | undefined ?? ''}`);
    }

    return formatString(folderParts[folderPartIndex] ?? '', format);
  }
}
