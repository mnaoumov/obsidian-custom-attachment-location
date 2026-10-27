import { getFileOrNull } from '@mnaoumov/obsidian-lib/file-system';
import { getNestedPropertyValue } from '@mnaoumov/typescript-lib/object-utils';
import { ensureGenericObject } from '@mnaoumov/typescript-lib/type-guards';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from '../base/token-base.ts';

const formatSchema = z.strictObject({
  key: z.string()
});
type Format = z.infer<typeof formatSchema>;

export class FrontmatterToken extends TokenBase<Format> {
  public constructor() {
    super('frontmatter', formatSchema);
  }

  protected override evaluateImpl(context: TokenEvaluatorContext, format: Format): string {
    const file = getFileOrNull({
      app: context.app,
      pathOrFile: context.noteFilePath
    });
    if (!file) {
      return '';
    }

    const cache = context.app.metadataCache.getFileCache(file);

    if (!cache?.frontmatter) {
      return '';
    }

    const value = getNestedPropertyValue(ensureGenericObject(cache.frontmatter), format.key) ?? '';
    // eslint-disable-next-line @typescript-eslint/no-base-to-string -- Need to convert to string.
    return String(value);
  }
}
