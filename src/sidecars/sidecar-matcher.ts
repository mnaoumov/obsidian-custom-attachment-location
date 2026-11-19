import {
  basename,
  extname
} from '@mnaoumov/typescript-lib/path';

export interface SidecarBase {
  readonly baseName: string;
  readonly shouldReplaceExtension?: boolean;
  readonly suffix: string;
}

interface FindSidecarBaseParams extends IsSidecarNameParams {
  readonly names: readonly string[];
}

interface IsSidecarNameParams {
  readonly extensions: readonly string[];
  readonly name: string;
}

/**
Finds an exact appended-name companion, or a unique non-sidecar with the same stem.

@returns The base, or `null` when the name is no sidecar or a sidecar with no unique base; tell those two apart with
`isSidecarName`.
*/
export function findSidecarBase(params: FindSidecarBaseParams): null | SidecarBase {
  if (!isSidecarName(params)) {
    return null;
  }
  const extension = extname(params.name);
  const extensions = normalizeExtensions(params.extensions);
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

/**
Whether a name has one of the sidecar extensions, whether or not a base for it exists.
*/
export function isSidecarName(params: IsSidecarNameParams): boolean {
  return normalizeExtensions(params.extensions).has(extname(params.name).slice(1).toLowerCase());
}

function normalizeExtensions(extensions: readonly string[]): Set<string> {
  return new Set(extensions.map((value) => value.trim().replace(/^\./u, '').toLowerCase()).filter(Boolean));
}
