import {
  afterEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import { selfWriteRegistry } from './self-write-registry.ts';

describe('selfWriteRegistry', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should not report a path that was never registered', () => {
    expect(selfWriteRegistry.consume('never-registered.png')).toBe(false);
  });

  it('should report a registered path exactly once', () => {
    selfWriteRegistry.register('assets/file.png');

    expect(selfWriteRegistry.consume('assets/file.png')).toBe(true);
    // Consuming un-claims it, so a later creation at the same path is treated as foreign again.
    expect(selfWriteRegistry.consume('assets/file.png')).toBe(false);
  });

  it('should keep registrations for distinct paths apart', () => {
    selfWriteRegistry.register('a.png');
    selfWriteRegistry.register('b.png');

    expect(selfWriteRegistry.consume('b.png')).toBe(true);
    expect(selfWriteRegistry.consume('a.png')).toBe(true);
  });

  it('should drop a registration that was never consumed, rather than leaking it forever', () => {
    vi.useFakeTimers();
    selfWriteRegistry.register('abandoned.png');

    // Past the prune threshold: a write that never produced a `create` event must not keep a claim
    // That would later swallow a genuinely foreign creation at the same path.
    vi.advanceTimersByTime(60_001);

    expect(selfWriteRegistry.consume('abandoned.png')).toBe(false);
  });
});
