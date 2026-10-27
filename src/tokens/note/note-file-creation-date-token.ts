import { DUMMY_PATH } from '@mnaoumov/obsidian-lib/attachment-path';
import { getFile } from '@mnaoumov/obsidian-lib/file-system';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  formatDate,
  momentJsFormatSchema,
  withMomentJsFormatShorthand
} from '../base/moment-js-token-base.ts';
import { TokenBase } from '../base/token-base.ts';

const formatSchema = withMomentJsFormatShorthand(z.strictObject({
  ...momentJsFormatSchema.shape
}));
type Format = z.output<typeof formatSchema>;

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
