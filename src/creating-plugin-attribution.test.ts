import {
  describe,
  expect,
  it
} from 'vitest';

import {
  captureStackTrace,
  findCreatingPluginId
} from './creating-plugin-attribution.ts';

const OWN_PLUGIN_ID = 'custom-attachment-location';

describe('captureStackTrace', () => {
  it('should return the current stack', () => {
    expect(captureStackTrace()).toContain('captureStackTrace');
  });

  it('should restore the stack trace limit it raised', () => {
    const originalStackTraceLimit = Error.stackTraceLimit;

    captureStackTrace();

    expect(Error.stackTraceLimit).toBe(originalStackTraceLimit);
  });
});

describe('findCreatingPluginId', () => {
  it('should return null for a stack with no plugin frame', () => {
    const stack = [
      'Error: Stack capture',
      '    at Vault.createBinary (app://obsidian.md/app.js:79355:20)',
      '    at Object.next (app://obsidian.md/app.js:12:1)'
    ].join('\n');

    expect(findCreatingPluginId(stack, OWN_PLUGIN_ID)).toBeNull();
  });

  it('should return the plugin of the nearest foreign frame', () => {
    const stack = [
      'Error: Stack capture',
      '    at captureStackTrace (plugin:custom-attachment-location:100:11)',
      '    at Vault.createBinary (app://obsidian.md/app.js:79355:20)',
      '    at DataviewJSRenderer.render (plugin:media-extended:19064:19)',
      '    at t.onload (plugin:excalidraw:512:7)'
    ].join('\n');

    expect(findCreatingPluginId(stack, OWN_PLUGIN_ID)).toBe('media-extended');
  });

  it('should return null when only this plugin is on the stack', () => {
    const stack = [
      'Error: Stack capture',
      '    at captureStackTrace (plugin:custom-attachment-location:100:11)',
      '    at AttachmentSaver.save (plugin:custom-attachment-location:220:9)'
    ].join('\n');

    expect(findCreatingPluginId(stack, OWN_PLUGIN_ID)).toBeNull();
  });

  it('should read the id out of a nested eval frame', () => {
    // The shape a plugin's own `eval` produces, e.g. Dataview running a user script.
    const stack = [
      'Error: Stack capture',
      '    at eval (eval at <anonymous> (plugin:dataview), <anonymous>:1:56)'
    ].join('\n');

    expect(findCreatingPluginId(stack, OWN_PLUGIN_ID)).toBe('dataview');
  });

  it('should stop the id at the path of a source-mapped frame', () => {
    // `obsidian-dev-utils` rewrites source-map sources to this shape, which a stack-mapping tool surfaces.
    const stack = [
      'Error: Stack capture',
      '    at save (app://obsidian.md/plugin:media-extended/src/screenshot.ts:12:3)'
    ].join('\n');

    expect(findCreatingPluginId(stack, OWN_PLUGIN_ID)).toBe('media-extended');
  });

  it('should decode an url-encoded id, as Obsidian encodes it when it builds the source URL', () => {
    const stack = [
      'Error: Stack capture',
      '    at write (plugin:my%20plugin:1:2)'
    ].join('\n');

    expect(findCreatingPluginId(stack, OWN_PLUGIN_ID)).toBe('my plugin');
  });

  it('should keep an id that does not decode, rather than throwing inside a vault write', () => {
    const stack = [
      'Error: Stack capture',
      '    at write (plugin:100%bad:1:2)'
    ].join('\n');

    expect(findCreatingPluginId(stack, OWN_PLUGIN_ID)).toBe('100%bad');
  });

  it('should return null for an empty stack', () => {
    expect(findCreatingPluginId('', OWN_PLUGIN_ID)).toBeNull();
  });
});
