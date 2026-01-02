import { getCacheSafe } from 'obsidian-dev-utils/obsidian/MetadataCache';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../TokenEvaluatorContext.ts';

import { TokenBase } from './TokenBase.ts';

const formatSchema = z.strictObject({
  level: z.enum(['1', '2', '3', '4', '5', '6', 'any']).optional().default('any')
});
type Format = z.infer<typeof formatSchema>;
type HeadingLevel = Format['level'];

export class HeadingToken extends TokenBase<Format> {
  public constructor() {
    super('heading', formatSchema);
  }

  protected override async evaluateImpl(ctx: TokenEvaluatorContext, format: Format): Promise<string> {
    const headingsInfo = await this.initHeadings(ctx);
    const rawHeading = headingsInfo.get(format.level) ?? '';
    return ctx.plugin.replaceSpecialCharacters(rawHeading);
  }

  private async initHeadings(ctx: TokenEvaluatorContext): Promise<Map<HeadingLevel, string>> {
    const headingsInfo = new Map<HeadingLevel, string>();

    if (!ctx.cursorLine) {
      return headingsInfo;
    }

    const cache = await getCacheSafe(ctx.app, ctx.noteFilePath);
    if (!cache?.headings) {
      return headingsInfo;
    }

    const lastLines = new Map<HeadingLevel, number>();

    for (const heading of cache.headings) {
      if (heading.position.start.line > ctx.cursorLine) {
        continue;
      }

      const headingLevel = String(heading.level) as HeadingLevel;

      const lastLine = lastLines.get(headingLevel) ?? -1;
      if (heading.position.start.line > lastLine) {
        headingsInfo.set(headingLevel, heading.heading);
        lastLines.set(headingLevel, heading.position.start.line);
        if (heading.position.start.line > (lastLines.get('any') ?? -1)) {
          lastLines.set('any', heading.position.start.line);
          headingsInfo.set('any', heading.heading);
        }
      }
    }

    return headingsInfo;
  }
}
