import { moment as moment_ } from 'obsidian';
import { extractDefaultExportInterop } from 'obsidian-dev-utils/ObjectUtils';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import {
  formatNow,
  momentJsFormatSchema
} from './MomentJsTokenBase.ts';
import { TokenBase } from './TokenBase.ts';

export const moment = extractDefaultExportInterop(moment_);

const formatSchema = z.strictObject({
  ...momentJsFormatSchema.shape
});
type Format = z.infer<typeof formatSchema>;

export class DateToken extends TokenBase<Format> {
  public constructor() {
    super('date', formatSchema);
  }

  protected override evaluateImpl(_ctx: TokenEvaluatorContext, format: Format): string {
    return formatNow(format);
  }
}
