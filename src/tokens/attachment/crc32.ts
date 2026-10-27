/* eslint-disable no-bitwise -- CRC-32 is defined in terms of bitwise operations. */

import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';

const CRC32_POLYNOMIAL = 0xED_B8_83_20;
const BYTE_VALUE_COUNT = 256;
const BITS_PER_BYTE = 8;
const BYTE_MASK = 0xFF;
const ALL_BITS = 0xFF_FF_FF_FF;
const CRC32_BYTE_LENGTH = 4;

const CRC32_TABLE = createCrc32Table();

// CRC-32 (IEEE 802.3, the one ZIP and SFV use), returned as its 4 bytes in big-endian order, so its hex reads the way Total Commander and `zlib.crc32` print it.
export function crc32(data: Uint8Array): Uint8Array {
  let crc = ALL_BITS;
  for (const byte of data) {
    crc = ensureNonNullable(CRC32_TABLE[(crc ^ byte) & BYTE_MASK]) ^ (crc >>> BITS_PER_BYTE);
  }
  const result = new Uint8Array(CRC32_BYTE_LENGTH);
  new DataView(result.buffer).setUint32(0, (crc ^ ALL_BITS) >>> 0);
  return result;
}

function createCrc32Table(): Uint32Array {
  const table = new Uint32Array(BYTE_VALUE_COUNT);
  for (let n = 0; n < BYTE_VALUE_COUNT; n++) {
    let c = n;
    for (let bit = 0; bit < BITS_PER_BYTE; bit++) {
      c = (c & 1) === 1 ? CRC32_POLYNOMIAL ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
}

/* eslint-enable no-bitwise -- End of the CRC-32 implementation. */
