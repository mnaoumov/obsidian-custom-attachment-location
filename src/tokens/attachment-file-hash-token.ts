import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { TokenBase } from './token-base.ts';

const formatSchema = z.strictObject({
  algorithm: z.enum(['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']).optional().default('SHA-256'),
  case: z.enum(['lower', 'upper']).optional().default('lower'),
  length: z.int().positive().optional()
});
type Format = z.infer<typeof formatSchema>;

const HEX_RADIX = 16;
const HEX_DIGITS_PER_BYTE = 2;

export class AttachmentFileHashToken extends TokenBase<Format> {
  public constructor() {
    super('attachmentFileHash', formatSchema);
  }

  protected override async evaluateImpl(context: TokenEvaluatorContext, format: Format): Promise<string> {
    // No attachment (token validation, a folder read through the API) hashes as empty content, the way `{{attachmentFileSize}}` reports `0`.
    const attachmentFileContent = await context.getAttachmentFileContent() ?? new ArrayBuffer(0);
    // eslint-disable-next-line n/no-unsupported-features/node-builtins -- crypto.subtle is the Web Crypto API, available in Obsidian's Electron renderer and on mobile; the rule incorrectly flags it as a Node experimental builtin.
    const digest = await crypto.subtle.digest(format.algorithm, attachmentFileContent);
    let hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(HEX_RADIX).padStart(HEX_DIGITS_PER_BYTE, '0')).join('');
    if (format.length !== undefined) {
      hash = hash.slice(0, format.length);
    }
    return format.case === 'upper' ? hash.toUpperCase() : hash;
  }
}
