import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({});
type Format = z.infer<typeof formatSchema>;

export class NoteFilePathToken extends TokenBase<Format> {
  public constructor() {
    super('noteFilePath', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext): string {
    return ctx.noteFilePath;
  }
}
