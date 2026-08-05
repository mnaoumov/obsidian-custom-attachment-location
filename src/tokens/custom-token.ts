import type { Promisable } from 'type-fest';

import { printError } from 'obsidian-dev-utils/error';
import { createFunction } from 'obsidian-dev-utils/function';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from './token-base.ts';

type TokenEvaluator = (context: TokenEvaluatorContext) => Promisable<string>;

const formatSchema = z.looseObject({});
type Format = z.infer<typeof formatSchema>;
type RegisterCustomTokenFunction = (token: string, evaluator: TokenEvaluator) => void;
type RegisterCustomTokensWrapperFunction = (registerCustomToken: RegisterCustomTokenFunction) => void;

export class CustomToken extends TokenBase<Format> {
  public constructor(name: string, private readonly evaluator: TokenEvaluator) {
    super(name, formatSchema);
  }

  public static parse(customTokensString: string): CustomToken[] | null {
    const customTokens: CustomToken[] = [];
    try {
      const registerCustomTokensWrapperFunction = createFunction<RegisterCustomTokensWrapperFunction>({
        argumentNames: ['registerCustomToken'],
        functionBody: customTokensString
      });

      registerCustomTokensWrapperFunction(registerCustomToken);
      return customTokens;
    } catch (error) {
      printError(new Error('Error registering custom tokens', { cause: error }));
      return null;
    }

    function registerCustomToken(token: string, evaluator: TokenEvaluator): void {
      customTokens.push(new CustomToken(token, evaluator));
    }
  }

  protected override async evaluateImpl(context: TokenEvaluatorContext): Promise<string> {
    return this.evaluator(context);
  }
}
