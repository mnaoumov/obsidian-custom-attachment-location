import { moment as moment_ } from 'obsidian';
import { extractDefaultExportInterop } from 'obsidian-dev-utils/ObjectUtils';
import { z } from 'zod';

export const moment = extractDefaultExportInterop(moment_);

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
