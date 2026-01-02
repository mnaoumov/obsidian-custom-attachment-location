import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/AttachmentPath';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import { promptWithPreview } from '../PromptWithPreviewModal.ts';
import { ActionContext } from '../TokenEvaluatorContext.ts';
import {
  formatString,
  stringFormatSchema
} from './StringTokenBase.ts';
import { TokenBase } from './TokenBase.ts';

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
          areTokensAllowed: false,
          path: value,
          plugin: ctx.plugin
        })
    });
    if (promptResult === null) {
      throw new Error('Prompt cancelled');
    }
    return formatString(promptResult, format);
  }
}
