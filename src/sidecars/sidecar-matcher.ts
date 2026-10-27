import {
  basename,
  extname
} from '@mnaoumov/typescript-lib/path';

export interface SidecarBase {
  readonly baseName: string;
  readonly shouldReplaceExtension?: boolean;
  readonly suffix: string;
}

interface FindSidecarBaseParams {
  readonly extensions: readonly string[];
  readonly name: string;
  readonly names: readonly string[];
}

/**
Finds an exact appended-name companion, or a unique non-sidecar with the same stem.
*/
export function findSidecarBase(params: FindSidecarBaseParams): null | SidecarBase | undefined {
  const extension = extname(params.name);
  const extensions = new Set(params.extensions.map((value) => value.trim().replace(/^\./u, '').toLowerCase()).filter(Boolean));
  if (!extensions.has(extension.slice(1).toLowerCase())) {
    return undefined;
  }
  const stem = basename(params.name, extension);
  const exact = params.names.filter((name) => name === stem);
  if (exact.length === 1) {
    return { baseName: stem, suffix: extension };
  }
  const candidates = params.names.filter((name) =>
    name !== params.name
    && !extensions.has(extname(name).slice(1).toLowerCase())
    && basename(name, extname(name)) === stem
  );
  return candidates.length === 1 && candidates[0] !== undefined
    ? { baseName: candidates[0], shouldReplaceExtension: true, suffix: extension }
    : null;
}

/**
Derives the companion path from the base's actual destination, including any collision suffix.
*/
export function getSidecarPath(basePath: string, pairing: SidecarBase): string {
  return (pairing.shouldReplaceExtension ? basePath.slice(0, basePath.length - extname(basePath).length) : basePath) + pairing.suffix;
}
