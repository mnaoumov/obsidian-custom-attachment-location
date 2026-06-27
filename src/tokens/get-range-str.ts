export function getRangeStr(from: string, to: string): string {
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
