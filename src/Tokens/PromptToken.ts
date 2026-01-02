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
  ...stringFormatSchema.shape
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
