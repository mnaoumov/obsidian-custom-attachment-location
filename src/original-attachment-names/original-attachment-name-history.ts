/**
 * A durable arrival or path lifecycle observation. Unique keys keep concurrent writers from replacing each other's history.
 */
export interface OriginalAttachmentNameOperation {
  /**
  Arrival name, for an arrival observation.
  */
  readonly fileName?: string;
  /**
  Whether a path operation includes descendants.
  */
  readonly isFolder?: boolean;
  /**
  Operation to replay.
  */
  readonly kind: 'arrival' | 'edit' | 'remove' | 'rename' | 'source-edit' | 'source';
  /**
  Arrival observations seen by a lifecycle action; protects later path reuse from duplicate events.
  */
  readonly observed?: readonly string[];
  /**
  Source path exposed by the importer, when available.
  */
  readonly originalPath?: string;
  /**
  Path at the time of the observation.
  */
  readonly path: string;
  /**
  Destination of a rename.
  */
  readonly target?: string;
  /**
  Logical wall time; legacy observations sort before every live operation.
  */
  readonly time: number;
}

/**
 * Rebuilds the synchronous lookup from immutable shared operations. Replaying the whole history also handles a
 * rename delivered before the corresponding arrival. Removals remain in history so late devices cannot resurrect it.
 */
export class OriginalAttachmentNameHistory {
  /**
  Current path to earliest arrival name.
  */
  public readonly names = new Map<string, string>();
  /**
  Source paths are optional and independent of names.
  */
  public readonly originalPaths = new Map<string, string>();
  /**
  Largest observed logical wall time.
  */
  public time = 0;
  private readonly identities = new Map<string, Set<string>>();
  private readonly operations = new Map<string, OriginalAttachmentNameOperation>();

  /**
   * Adds a locally ordered operation without replaying the history on every attachment import.
   *
   * @param key - Unique immutable operation id.
   * @param operation - Validated local operation.
   */
  public add(key: string, operation: OriginalAttachmentNameOperation): void {
    this.operations.set(key, operation);
    this.time = Math.max(this.time, operation.time);
    this.apply(key, operation);
  }

  /**
   * Identifies the arrivals currently known at a path.
   *
   * @param path - Current vault path.
   * @returns Observation ids, detached from the projection.
   */
  public getObserved(path: string): string[] {
    return [...this.identities.get(path) ?? []];
  }

  /**
   * Joins delivered operations and rebuilds the lookup in deterministic order.
   *
   * @param entries - Untrusted shared records.
   */
  public merge(entries: readonly (readonly [string, unknown])[]): void {
    for (const [key, value] of entries) {
      if (!isOperation(value)) {
        continue;
      }

      this.operations.set(key, value);
      this.time = Math.max(this.time, value.time);
    }
    this.names.clear();
    this.originalPaths.clear();
    this.identities.clear();
    const ordered = [...this.operations].sort(([firstKey, first], [secondKey, second]) => first.time - second.time || (firstKey < secondKey ? -1 : Number(firstKey > secondKey)));
    for (const [key, operation] of ordered) {
      this.apply(key, operation);
    }
  }

  private apply(key: string, operation: OriginalAttachmentNameOperation): void {
    if (operation.kind === 'remove' || operation.kind === 'rename') {
      this.applyLifecycle(operation);
      return;
    }
    const identities = this.identities.get(operation.path) ?? new Set<string>();
    identities.add(key);
    this.identities.set(operation.path, identities);
    const isSource = operation.kind === 'source' || operation.kind === 'source-edit';
    const records = isSource ? this.originalPaths : this.names;
    const value = isSource ? operation.originalPath : operation.fileName;
    if (value !== undefined && (operation.kind === 'edit' || operation.kind === 'source-edit' || !records.has(operation.path))) {
      records.set(operation.path, value);
    }
  }

  private applyLifecycle(operation: OriginalAttachmentNameOperation): void {
    const paths = operation.isFolder
      ? [...new Set([...this.names.keys(), ...this.originalPaths.keys()])].filter((path) => path.startsWith(`${operation.path}/`))
      : [operation.path];
    for (const path of paths) {
      const identities = this.identities.get(path);
      if (operation.observed?.every((id) => !(identities?.has(id) ?? false))) {
        continue;
      }
      this.identities.delete(path);
      if (identities && operation.kind === 'rename' && operation.target !== undefined) {
        const target = operation.target + path.slice(operation.path.length);
        this.identities.set(target, new Set([...this.identities.get(target) ?? [], ...identities]));
      }
      for (const records of [this.names, this.originalPaths]) {
        const value = records.get(path);
        records.delete(path);
        if (value === undefined || operation.kind !== 'rename' || operation.target === undefined) {
          continue;
        }
        const target = operation.target + path.slice(operation.path.length);
        if (!records.has(target)) {
          records.set(target, value);
        }
      }
    }
  }
}

function checkOptionalFields(record: Partial<Record<keyof OriginalAttachmentNameOperation, unknown>>): boolean {
  return (record.isFolder === undefined || typeof record.isFolder === 'boolean')
    && (record.observed === undefined || (Array.isArray(record.observed) && record.observed.every((id: unknown) => typeof id === 'string')));
}

function isOperation(value: unknown): value is OriginalAttachmentNameOperation {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Partial<Record<keyof OriginalAttachmentNameOperation, unknown>>;
  if (typeof record.path !== 'string' || typeof record.time !== 'number' || !Number.isFinite(record.time) || !checkOptionalFields(record)) {
    return false;
  }
  switch (record.kind) {
    case 'arrival':
    case 'edit': {
      return typeof record.fileName === 'string';
    }
    case 'remove': {
      return true;
    }
    case 'rename': {
      return typeof record.target === 'string';
    }
    case 'source':
    case 'source-edit': {
      return typeof record.originalPath === 'string' && record.originalPath.length > 0;
    }
    default: {
      return false;
    }
  }
}
