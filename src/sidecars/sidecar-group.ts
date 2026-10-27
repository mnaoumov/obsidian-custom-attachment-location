import type {
  App,
  TFile
} from 'obsidian';

import {
  getAbstractFileOrNull,
  isFile
} from '@mnaoumov/obsidian-lib/file-system';
import {
  copySafe,
  trashSafe
} from '@mnaoumov/obsidian-lib/vault';
import {
  basename,
  dirname,
  join
} from '@mnaoumov/typescript-lib/path';
import { ensureNonNullable } from '@mnaoumov/typescript-lib/type-guards';

import {
  findSidecarBase,
  getSidecarPath
} from './sidecar-matcher.ts';

interface CopyWithSidecarsParams {
  readonly app: App;
  readonly existingFile?: null | TFile;
  readonly extensions: readonly string[];
  readonly newPath: string;
  readonly oldPathOrFile: string | TFile;
}

interface FindReusedCompanionsParams {
  readonly app: App;
  readonly destinations: ReadonlyMap<string, string>;
  readonly shouldReuse: boolean;
}

interface GetCompanionDestinationsParams {
  readonly basePath: string;
  readonly extensions: readonly string[];
  readonly oldPath: string;
  readonly paths: readonly string[];
}

interface GetSidecarGroupPathsParams {
  readonly extensions: readonly string[];
  readonly path: string;
  readonly paths: readonly string[];
}

/**
Copies descendants using the base's actual destination and rolls back incomplete groups.
*/
export async function copyWithSidecars(params: CopyWithSidecarsParams): Promise<string> {
  const { app, extensions } = params;
  const oldPath = typeof params.oldPathOrFile === 'string' ? params.oldPathOrFile : params.oldPathOrFile.path;
  const paths = extensions.length > 0 ? app.vault.getFiles().map((file) => file.path).filter((path) => dirname(path) === dirname(oldPath)) : [];
  const copiedPaths: string[] = [];
  try {
    const basePath = params.existingFile?.path ?? await copySafe({ app, newPath: params.newPath, oldPathOrFile: params.oldPathOrFile });
    if (basePath === oldPath) {
      return basePath;
    }
    if (!params.existingFile) {
      copiedPaths.push(basePath);
    }
    const destinations = getCompanionDestinations({ basePath, extensions, oldPath, paths });
    const reusedPaths = await findReusedCompanions({ app, destinations, shouldReuse: !!params.existingFile });
    for (const [sourcePath, destinationPath] of destinations) {
      if (reusedPaths.has(sourcePath)) {
        continue;
      }
      const copiedPath = await copySafe({ app, newPath: destinationPath, oldPathOrFile: sourcePath });
      copiedPaths.push(copiedPath);
      if (copiedPath !== destinationPath) {
        throw new Error(`Sidecar destination changed: ${destinationPath}`);
      }
    }
    return basePath;
  } catch (error) {
    for (const path of copiedPaths.reverse()) {
      await trashSafe(app, ensureNonNullable(app.vault.getFileByPath(path)));
    }
    throw error;
  }
}

/**
Returns the connected companion group, including bases of linked signatures.
*/
export function getSidecarGroupPaths(params: GetSidecarGroupPathsParams): string[] {
  if (params.extensions.length === 0) {
    return [params.path];
  }
  const siblings = params.paths.filter((path) => dirname(path) === dirname(params.path));
  const names = siblings.map((path) => basename(path));
  const group = new Set([params.path]);
  let previousSize = 0;
  while (previousSize !== group.size) {
    previousSize = group.size;
    for (const path of siblings) {
      const pairing = findSidecarBase({ extensions: params.extensions, name: basename(path), names });
      if (!pairing) {
        continue;
      }
      const basePath = join(dirname(path), pairing.baseName);
      if (!(group.has(path) || group.has(basePath))) {
        continue;
      }

      group.add(path);
      group.add(basePath);
    }
  }
  return siblings.filter((path) => group.has(path));
}

async function findReusedCompanions(params: FindReusedCompanionsParams): Promise<Set<string>> {
  const { app } = params;
  const companionDestinations = new Set<string>();
  const reusedPaths = new Set<string>();
  for (const [sourcePath, destinationPath] of params.destinations) {
    if (companionDestinations.has(destinationPath.toLowerCase())) {
      throw new Error(`Sidecar destination exists: ${destinationPath}`);
    }
    companionDestinations.add(destinationPath.toLowerCase());
    const occupant = getAbstractFileOrNull({ app, isCaseInsensitive: true, pathOrFile: destinationPath });
    if (!occupant) {
      continue;
    }
    if (params.shouldReuse && isFile(occupant)) {
      const source = new Uint8Array(await app.vault.readBinary(ensureNonNullable(app.vault.getFileByPath(sourcePath))));
      const target = new Uint8Array(await app.vault.readBinary(occupant));
      if (source.length === target.length && source.every((value, index) => value === target[index])) {
        reusedPaths.add(sourcePath);
        continue;
      }
    }
    throw new Error(`Sidecar destination exists: ${destinationPath}`);
  }
  return reusedPaths;
}

function getCompanionDestinations(params: GetCompanionDestinationsParams): Map<string, string> {
  const names = params.paths.map((path) => basename(path));
  const destinations = new Map<string, string>();
  const queue = [{ destinationPath: params.basePath, sourcePath: params.oldPath }];
  const queued = new Set([params.oldPath]);
  let index = 0;
  while (index < queue.length) {
    const current = ensureNonNullable(queue[index++]);
    for (const path of params.paths) {
      if (queued.has(path)) {
        continue;
      }
      const pairing = findSidecarBase({ extensions: params.extensions, name: basename(path), names });
      if (pairing?.baseName !== basename(current.sourcePath)) {
        continue;
      }
      const destinationPath = getSidecarPath(current.destinationPath, pairing);
      destinations.set(path, destinationPath);
      queued.add(path);
      queue.push({ destinationPath, sourcePath: path });
    }
  }
  return destinations;
}
