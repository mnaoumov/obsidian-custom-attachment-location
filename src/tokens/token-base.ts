import type { Promisable } from 'type-fest';

import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

export abstract class TokenBase<TFormat> {
  public constructor(public readonly name: string, private readonly formatSchema: z.ZodType<TFormat>) {}

  public evaluate(context: TokenEvaluatorContext): Promisable<string> {
    const format = context.format === null ? this.getDefaultFormat() : this.formatSchema.parse(context.format);
    return this.evaluateImpl(context, format);
  }

  protected abstract evaluateImpl(context: TokenEvaluatorContext, format: TFormat): Promisable<string>;

  private getDefaultFormat(): TFormat {
    const result = this.formatSchema.safeParse({});
    if (!result.success) {
      throw new Error(`Token ${this.name} does not support default format.`);
    }
    return result.data;
  }
}
