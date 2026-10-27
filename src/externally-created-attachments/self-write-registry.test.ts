import {
  afterEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import {
  SelfWriteClaim,
  selfWriteRegistry
} from './self-write-registry.ts';

describe('selfWriteRegistry', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should not report a path that was never registered', () => {
    expect(selfWriteRegistry.consume('never-registered.png')).toBe(SelfWriteClaim.None);
  });

  it('should report a registered path exactly once', () => {
    selfWriteRegistry.register('assets/file.png');

    expect(selfWriteRegistry.consume('assets/file.png')).toBe(SelfWriteClaim.Plugin);
    // Consuming un-claims it, so a later creation at the same path is treated as foreign again.
    expect(selfWriteRegistry.consume('assets/file.png')).toBe(SelfWriteClaim.None);
  });

  it('should keep registrations for distinct paths apart', () => {
    selfWriteRegistry.register('a.png');
    selfWriteRegistry.register('b.png');

    expect(selfWriteRegistry.consume('b.png')).toBe(SelfWriteClaim.Plugin);
    expect(selfWriteRegistry.consume('a.png')).toBe(SelfWriteClaim.Plugin);
  });

  it('should report a path resolved for an outside caller as that kind of claim, exactly once', () => {
    selfWriteRegistry.register('assets/outside.png', SelfWriteClaim.OutsideCaller);

    expect(selfWriteRegistry.hasOutsideCallerClaim('assets/outside.png')).toBe(true);
    expect(selfWriteRegistry.consume('assets/outside.png')).toBe(SelfWriteClaim.OutsideCaller);
    expect(selfWriteRegistry.hasOutsideCallerClaim('assets/outside.png')).toBe(false);
    expect(selfWriteRegistry.consume('assets/outside.png')).toBe(SelfWriteClaim.None);
  });

  it('should not report the plugin\'s own claim as one made for an outside caller', () => {
    selfWriteRegistry.register('assets/own.png');

    // Peeking must leave the claim in place for the `create` handler to consume.
    expect(selfWriteRegistry.hasOutsideCallerClaim('assets/own.png')).toBe(false);
    expect(selfWriteRegistry.consume('assets/own.png')).toBe(SelfWriteClaim.Plugin);
  });

  it('should let the latest claim on a path win', () => {
    selfWriteRegistry.register('assets/reclaimed.png', SelfWriteClaim.OutsideCaller);
    selfWriteRegistry.register('assets/reclaimed.png');

    expect(selfWriteRegistry.consume('assets/reclaimed.png')).toBe(SelfWriteClaim.Plugin);
  });

  it('should drop a registration that was never consumed, rather than leaking it forever', () => {
    vi.useFakeTimers();
    selfWriteRegistry.register('abandoned.png');
    selfWriteRegistry.register('abandoned-outside.png', SelfWriteClaim.OutsideCaller);

    // Past the prune threshold: a write that never produced a `create` event must not keep a claim
    // that would later swallow a genuinely foreign creation at the same path.
    vi.advanceTimersByTime(60_001);

    expect(selfWriteRegistry.hasOutsideCallerClaim('abandoned-outside.png')).toBe(false);
    expect(selfWriteRegistry.consume('abandoned.png')).toBe(SelfWriteClaim.None);
  });
});
