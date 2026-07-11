interface GetRangeStrParams {
  readonly from: string;
  readonly to: string;
}

export function getRangeStr(params: GetRangeStrParams): string {
  const { from, to } = params;
  if (from.length !== 1) {
    throw new Error(`Range must be from-to a single character: ${from} to ${to}`);
  }
  if (to.length !== 1) {
    throw new Error(`Range must be from-to a single character: ${from} to ${to}`);
  }

  let str = '';

  for (let i = from.charCodeAt(0); i <= to.charCodeAt(0); i++) {
    str += String.fromCharCode(i);
  }

  return str;
}
