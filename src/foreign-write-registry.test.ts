import {
  afterEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { foreignWriteRegistry } from './foreign-write-registry.ts';

describe('foreignWriteRegistry', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should not attribute a path that was never registered', () => {
    expect(foreignWriteRegistry.consume('never-registered.png')).toBeNull();
  });

  it('should attribute a registered path exactly once', () => {
    foreignWriteRegistry.register('assets/file.png', 'media-extended');

    expect(foreignWriteRegistry.consume('assets/file.png')).toBe('media-extended');
    // Consuming un-registers it, so a later creation at the same path is unattributed again.
    expect(foreignWriteRegistry.consume('assets/file.png')).toBeNull();
  });

  it('should keep registrations for distinct paths apart', () => {
    foreignWriteRegistry.register('a.png', 'first-plugin');
    foreignWriteRegistry.register('b.png', 'second-plugin');

    expect(foreignWriteRegistry.consume('b.png')).toBe('second-plugin');
    expect(foreignWriteRegistry.consume('a.png')).toBe('first-plugin');
  });

  it('should let the innermost write win for the same path', () => {
    // A plugin reaching the disk through `vault.createBinary` also passes `adapter.writeBinary`, so one
    // File is registered more than once. The last registration is the call that actually created it.
    foreignWriteRegistry.register('assets/file.png', 'outer-plugin');
    foreignWriteRegistry.register('assets/file.png', 'inner-plugin');

    expect(foreignWriteRegistry.consume('assets/file.png')).toBe('inner-plugin');
  });

  it('should drop a registration that was never consumed, rather than leaking it forever', () => {
    vi.useFakeTimers();
    foreignWriteRegistry.register('abandoned.png', 'media-extended');

    // Past the prune threshold: a write that never produced a `create` event must not keep attributing
    // A path that some other writer may later create.
    vi.advanceTimersByTime(60_001);

    expect(foreignWriteRegistry.consume('abandoned.png')).toBeNull();
  });
});
