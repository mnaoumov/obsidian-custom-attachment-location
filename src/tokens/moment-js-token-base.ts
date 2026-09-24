import { moment as moment_ } from 'obsidian';
import { extractDefaultExportInterop } from 'obsidian-dev-utils/object-utils';
import { z } from 'zod';

const moment = extractDefaultExportInterop(moment_);

export const momentJsFormatSchema = z.strictObject({
  momentJsFormat: z.string()
});
type Format = z.infer<typeof momentJsFormatSchema>;

export function formatDate(unixTimestampInMilliseconds: number, format: Format): string {
  return moment(unixTimestampInMilliseconds).format(format.momentJsFormat);
}

export function formatNow(format: Format): string {
  return moment().format(format.momentJsFormat);
}

/**
 * Lets a date-family token's format schema take the scalar shorthand.
 *
 * Besides the `{momentJsFormat: '...'}` object, the returned schema accepts a bare string as sugar for it, so the
 * core Templates form `{{date:YYYY-MM-DD}}` means `{{date:{momentJsFormat:'YYYY-MM-DD'}}}`. Every other key of the
 * schema keeps its default. The five date-family tokens are the only ones built on {@link momentJsFormatSchema}, so
 * the shorthand is unambiguous.
 *
 * @param schema - The token's own object schema.
 * @returns The schema, accepting a bare string too.
 */
export function withMomentJsFormatShorthand<TSchema extends z.ZodType>(schema: TSchema): z.ZodType<z.output<TSchema>> {
  return z.preprocess((format) => typeof format === 'string' ? { momentJsFormat: format } : format, schema);
}
