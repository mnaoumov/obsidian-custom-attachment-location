import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import { getFile } from 'obsidian-dev-utils/obsidian/file-system';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  formatDate,
  momentJsFormatSchema
} from './moment-js-token-base.ts';
import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({
  ...momentJsFormatSchema.shape
});
type Format = z.infer<typeof formatSchema>;

export class NoteFileModificationDateToken extends TokenBase<Format> {
  public constructor() {
    super('noteFileModificationDate', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    if (ctx.noteFilePath === DUMMY_PATH) {
      return formatDate(Date.now(), format);
    }
    const noteFile = getFile(ctx.app, ctx.noteFilePath);
    return formatDate(noteFile.stat.mtime, format);
  }
}
