import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import {
  formatNow,
  momentJsFormatSchema,
  withMomentJsFormatShorthand
} from './moment-js-token-base.ts';
import { TokenBase } from './token-base.ts';

const formatSchema = withMomentJsFormatShorthand(z.strictObject({
  ...momentJsFormatSchema.shape
}));
type Format = z.output<typeof formatSchema>;

export class DateToken extends TokenBase<Format> {
  public constructor() {
    super('date', formatSchema);
  }

  protected override evaluateImpl(_context: TokenEvaluatorContext, format: Format): string {
    return formatNow(format);
  }
}
