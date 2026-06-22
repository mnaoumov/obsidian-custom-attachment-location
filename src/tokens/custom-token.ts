import type { Promisable } from 'type-fest';

import { printError } from 'obsidian-dev-utils/error';
import { createFunction } from 'obsidian-dev-utils/function';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from './token-base.ts';

export type TokenEvaluator = (ctx: TokenEvaluatorContext) => Promisable<string>;

const formatSchema = z.looseObject({});
type Format = z.infer<typeof formatSchema>;
type RegisterCustomTokenFn = (token: string, evaluator: TokenEvaluator) => void;
type RegisterCustomTokensWrapperFn = (registerCustomToken: RegisterCustomTokenFn) => void;

export class CustomToken extends TokenBase<Format> {
  public constructor(name: string, private readonly evaluator: TokenEvaluator) {
    super(name, formatSchema);
  }

  public static parse(customTokensStr: string): CustomToken[] | null {
    const customTokens: CustomToken[] = [];
    try {
      const registerCustomTokensWrapperFn = createFunction<RegisterCustomTokensWrapperFn>({
        argNames: ['registerCustomToken'],
        functionBody: customTokensStr
      });

      registerCustomTokensWrapperFn(registerCustomToken);
      return customTokens;
    } catch (e) {
      printError(new Error('Error registering custom tokens', { cause: e }));
      return null;
    }

    function registerCustomToken(token: string, evaluator: TokenEvaluator): void {
      customTokens.push(new CustomToken(token, evaluator));
    }
  }

  protected override async evaluateImpl(ctx: TokenEvaluatorContext): Promise<string> {
    return this.evaluator(ctx);
  }
}
