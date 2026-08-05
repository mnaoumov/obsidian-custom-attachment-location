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

export class NoteFileCreationDateToken extends TokenBase<Format> {
  public constructor() {
    super('noteFileCreationDate', formatSchema);
  }

  protected override evaluateImpl(context: TokenEvaluatorContext, format: Format): string {
    if (context.noteFilePath === DUMMY_PATH) {
      return formatDate(Date.now(), format);
    }
    const noteFile = getFile({
      app: context.app,
      pathOrFile: context.noteFilePath
    });
    return formatDate(noteFile.stat.ctime, format);
  }
}
