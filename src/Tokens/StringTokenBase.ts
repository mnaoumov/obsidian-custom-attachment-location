import { extractDefaultExportInterop } from 'obsidian-dev-utils/ObjectUtils';
// eslint-disable-next-line import-x/no-rename-default -- Need to rename default export.
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
  switch (format.trim?.side) {
    case 'left':
      value = value.slice(0, format.trim.length);
      break;
    case 'right':
      value = value.slice(-format.trim.length);
      break;
    case undefined:
      break;
    default:
      throw new Error(`Invalid trim side: ${format.trim?.side as string | undefined ?? ''}`);
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
