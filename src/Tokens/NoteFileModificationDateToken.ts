import { getFile } from 'obsidian-dev-utils/obsidian/FileSystem';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import {
  formatDate,
  momentJsFormatSchema
} from './MomentJsTokenBase.ts';
import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({
  ...momentJsFormatSchema.shape
});
type Format = z.infer<typeof formatSchema>;

export class NoteFileModificationDateToken extends TokenBase<Format> {
  public constructor() {
    super('noteFileModificationDate', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    const noteFile = getFile(ctx.app, ctx.noteFilePath);
    return formatDate(noteFile.stat.mtime, format);
  }
}
