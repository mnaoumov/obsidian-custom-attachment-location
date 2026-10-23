import { blake3 } from '@noble/hashes/blake3.js';
import {
  md5,
  sha1
} from '@noble/hashes/legacy.js';
import {
  sha224,
  sha256,
  sha384,
  sha512
} from '@noble/hashes/sha2.js';
import {
  sha3_224 as sha3With224Bits,
  sha3_256 as sha3With256Bits,
  sha3_384 as sha3With384Bits,
  sha3_512 as sha3With512Bits
} from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { z } from 'zod';

import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { crc32 } from '../crc32.ts';
import { TokenBase } from './token-base.ts';

// The checksums Total Commander offers, under their standard names.
const formatSchema = z.strictObject({
  algorithm: z.enum([
    'BLAKE3',
    'CRC32',
    'MD5',
    'SHA-1',
    'SHA-224',
    'SHA-256',
    'SHA-384',
    'SHA-512',
    'SHA3-224',
    'SHA3-256',
    'SHA3-384',
    'SHA3-512'
  ]).optional().default('SHA-256'),
  case: z.enum(['lower', 'upper']).optional().default('lower'),
  length: z.int().positive().optional()
});
type Format = z.infer<typeof formatSchema>;

const HASH_FUNCTIONS: Record<Format['algorithm'], (data: Uint8Array) => Uint8Array> = {
  'BLAKE3': blake3,
  'CRC32': crc32,
  'MD5': md5,
  'SHA-1': sha1,
  'SHA-224': sha224,
  'SHA-256': sha256,
  'SHA-384': sha384,
  'SHA-512': sha512,
  'SHA3-224': sha3With224Bits,
  'SHA3-256': sha3With256Bits,
  'SHA3-384': sha3With384Bits,
  'SHA3-512': sha3With512Bits
};

export class AttachmentFileHashToken extends TokenBase<Format> {
  public constructor() {
    super('attachmentFileHash', formatSchema);
  }

  protected override async evaluateImpl(context: TokenEvaluatorContext, format: Format): Promise<string> {
    // No attachment (token validation, a folder read through the API) hashes as empty content, the way `{{attachmentFileSize}}` reports `0`.
    const attachmentFileContent = await context.getAttachmentFileContent() ?? new ArrayBuffer(0);
    let hash = bytesToHex(HASH_FUNCTIONS[format.algorithm](new Uint8Array(attachmentFileContent)));
    if (format.length !== undefined) {
      hash = hash.slice(0, format.length);
    }
    return format.case === 'upper' ? hash.toUpperCase() : hash;
  }
}
