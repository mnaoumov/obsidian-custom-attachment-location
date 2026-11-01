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
  readonly kind: 'arrival' | 'edit' | 'remove' | 'rename';
  /**
  Arrival observations seen by a lifecycle action; protects later path reuse from duplicate events.
  */
  readonly observed?: readonly string[];
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
    if (operation.fileName !== undefined && (operation.kind === 'edit' || !this.names.has(operation.path))) {
      this.names.set(operation.path, operation.fileName);
    }
  }

  private applyLifecycle(operation: OriginalAttachmentNameOperation): void {
    const paths = operation.isFolder
      ? [...this.names.keys()].filter((path) => path.startsWith(`${operation.path}/`))
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
      const value = this.names.get(path);
      this.names.delete(path);
      if (value === undefined || operation.kind !== 'rename' || operation.target === undefined) {
        continue;
      }
      const target = operation.target + path.slice(operation.path.length);
      if (!this.names.has(target)) {
        this.names.set(target, value);
      }
    }
  }
}

/**
 * Detects an observation of the retired source-path kinds, which 17.1.0 recorded beside the names.
 *
 * @param value - An untrusted shared record.
 * @returns Whether the record is a `source` or `source-edit` observation.
 */
export function isRetiredSourcePathOperation(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const kind = (value as Partial<Record<'kind', unknown>>).kind;
  return kind === 'source' || kind === 'source-edit';
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
    default: {
      // Includes the retired `source` and `source-edit` observations, which carried an import's source path.
      return false;
    }
  }
}
