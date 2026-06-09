import { extractDefaultExportInterop } from 'obsidian-dev-utils/object-utils';
import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';
import slugify_ from 'slugify';
import { z } from 'zod';

const slugify = extractDefaultExportInterop(slugify_);

export const stringFormatSchema = z.strictObject({
  case: z.enum(['lower', 'upper']).optional(),
  slugify: z.boolean().optional(),
  trim: z.strictObject({
    length: z.int().positive(),
    side: z.enum(['left', 'right'])
  }).optional()
});

type StringFormat = z.infer<typeof stringFormatSchema>;

export function formatString(value: string, format: StringFormat): string {
  const trim = format.trim;
  switch (trim?.side) {
    case 'left':
      value = value.slice(0, trim.length);
      break;
    case 'right':
      value = value.slice(-trim.length);
      break;
    case undefined:
      break;
    default:
      throw new Error(`Invalid trim side: ${ensureNonNullable(trim).side as string}`);
  }

  if (format.slugify) {
    value = slugify(value);
  }

  switch (format.case) {
    case 'lower':
      return value.toLowerCase();
    case undefined:
      return value;
    case 'upper':
      return value.toUpperCase();
    default:
      throw new Error(`Invalid case: ${format.case as string}`);
  }
}
