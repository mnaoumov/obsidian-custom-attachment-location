import { ensureNonNullable } from 'obsidian-dev-utils/type-guards';

interface GetRangeStringParams {
  readonly from: string;
  readonly to: string;
}

export function getRangeString(params: GetRangeStringParams): string {
  const { from, to } = params;
  if (from.length !== 1) {
    throw new Error(`Range must be from-to a single character: ${from} to ${to}`);
  }
  if (to.length !== 1) {
    throw new Error(`Range must be from-to a single character: ${from} to ${to}`);
  }

  let $string = '';

  // The single-character guards above make both code points defined.
  for (let index = ensureNonNullable(from.codePointAt(0)); index <= ensureNonNullable(to.codePointAt(0)); index++) {
    $string += String.fromCodePoint(index);
  }

  return $string;
}
