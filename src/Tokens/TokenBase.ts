import type { Promisable } from 'type-fest';

import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

export abstract class TokenBase<TFormat> {
  public constructor(public readonly name: string, private readonly formatSchema: z.ZodType<TFormat>) {
  }

  public evaluate(ctx: TokenEvaluatorContext): Promisable<string> {
    const format = ctx.format === null ? this.getDefaultFormat() : this.formatSchema.parse(ctx.format);
    return this.evaluateImpl(ctx, format);
  }

  protected abstract evaluateImpl(ctx: TokenEvaluatorContext, format: TFormat): Promisable<string>;

  protected getDefaultFormat(): TFormat {
    const result = this.formatSchema.safeParse({});
    if (!result.success) {
      throw new Error(`Token ${this.name} does not support default format.`);
    }
    return result.data;
  }
}
