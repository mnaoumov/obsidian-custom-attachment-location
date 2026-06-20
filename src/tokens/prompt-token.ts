import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { promptWithPreview } from '../prompt-with-preview-modal.ts';
import { ActionContext } from '../token-evaluator-context.ts';
import {
  formatString,
  stringFormatSchema
} from './string-token-base.ts';
import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({
  ...stringFormatSchema.shape,
  // eslint-disable-next-line no-template-curly-in-string -- Valid token.
  defaultValueTemplate: z.string().optional().default('${originalAttachmentFileName}')
});
type Format = z.infer<typeof formatSchema>;

export class PromptToken extends TokenBase<Format> {
  public constructor() {
    super('prompt', formatSchema);
  }

  protected override async evaluateImpl(ctx: TokenEvaluatorContext, format: Format): Promise<string> {
    if (ctx.actionContext === ActionContext.ValidateTokens || ctx.originalAttachmentFileName === DUMMY_PATH) {
      return DUMMY_PATH;
    }

    const promptResult = await promptWithPreview({
      ctx,
      defaultValue: format.defaultValueTemplate,
      valueValidator: (value) =>
        ctx.validatePath({
          app: ctx.app,
          areTokensAllowed: false,
          path: value,
          pluginSettingsComponent: ctx.pluginSettingsComponent
        })
    });
    if (promptResult === null) {
      throw new Error('Prompt cancelled');
    }
    return formatString(promptResult, format);
  }
}
