import {
  describe,
  expect,
  it
} from 'vitest';

import { isCleanupPluginReady } from './cleanup-plugin-readiness.ts';

describe('Desktop cleanup plugin readiness', () => {
  const previousPlugin = {};
  const previousApi = {};
  const ready = {
    currentPlugin: {},
    dependencyApis: [{ api: {}, isRevoked: false }],
    dependencyPlugin: {},
    pluginApis: [{ api: {}, isRevoked: false }],
    previousApis: [previousApi],
    previousPlugin
  };

  it('accepts a fresh published surface with its dependency present', () => {
    expect(isCleanupPluginReady(ready)).toBe(true);
  });

  it('rejects an absent plugin or the previous plugin instance', () => {
    expect(isCleanupPluginReady({ ...ready, currentPlugin: undefined })).toBe(false);
    expect(isCleanupPluginReady({ ...ready, currentPlugin: previousPlugin })).toBe(false);
  });

  it('rejects the previous API even after a new plugin instance appears', () => {
    expect(isCleanupPluginReady({ ...ready, pluginApis: [{ api: previousApi, isRevoked: false }] })).toBe(false);
  });

  it('waits until a live API is published by the new surface', () => {
    expect(isCleanupPluginReady({ ...ready, pluginApis: [] })).toBe(false);
    expect(isCleanupPluginReady({ ...ready, pluginApis: [{ api: {}, isRevoked: true }] })).toBe(false);
  });

  it('rejects an absent dependency or its unpublished or revoked API', () => {
    expect(isCleanupPluginReady({ ...ready, dependencyPlugin: undefined })).toBe(false);
    expect(isCleanupPluginReady({ ...ready, dependencyApis: [] })).toBe(false);
    expect(isCleanupPluginReady({ ...ready, dependencyApis: [{ api: {}, isRevoked: true }] })).toBe(false);
  });
});
