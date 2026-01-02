import { getNestedPropertyValue } from 'obsidian-dev-utils/ObjectUtils';
import { getFileOrNull } from 'obsidian-dev-utils/obsidian/FileSystem';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({
  key: z.string()
});
type Format = z.infer<typeof formatSchema>;

export class FrontmatterToken extends TokenBase<Format> {
  public constructor() {
    super('frontmatter', formatSchema);
  }

  protected override evaluateImpl(ctx: TokenEvaluatorContext, format: Format): string {
    const file = getFileOrNull(ctx.app, ctx.noteFilePath);
    if (!file) {
      return '';
    }

    const cache = ctx.app.metadataCache.getFileCache(file);

    if (!cache?.frontmatter) {
      return '';
    }

    const value = getNestedPropertyValue(cache.frontmatter, format.key) ?? '';
    // eslint-disable-next-line @typescript-eslint/no-base-to-string -- Need to convert to string.
    return String(value);
  }
}
