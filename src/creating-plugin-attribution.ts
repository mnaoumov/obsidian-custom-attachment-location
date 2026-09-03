/**
 * @file
 *
 * Reads the id of the community plugin whose code is on the current call stack.
 *
 * Obsidian evaluates every community plugin's `main.js` under a `plugin:` source URL:
 *
 * ```js
 * window.eval('(function anonymous(require,module,exports){' + code + '\n})\n//# sourceURL=plugin:' + encodeURIComponent(id));
 * ```
 *
 * so a frame that originated in a plugin's bundle reads `at fn (plugin:<url-encoded-id>:<line>:<col>)`.
 * That is the only attribution Obsidian offers — `vault.on('create')` says nothing about who wrote the
 * file — and Obsidian itself relies on it, matching `/plugin:([^:]+)/` against `new Error().stack` to name
 * the plugin that omitted a `Component` in `MarkdownRenderer.render`.
 *
 * It is best-effort by nature, and the settings description says so:
 *
 * - core Obsidian, a sync client and a raw `fs` write leave NO `plugin:` frame, so "no marker" means
 *   "unattributable", never "no plugin";
 * - a plugin that defers its write past an event-loop turn it does not own is no longer on the stack when
 *   the write happens.
 */

import { getStackTrace } from 'obsidian-dev-utils/error';

/**
 * Matches a frame produced by community-plugin code.
 *
 * The id is everything up to the `:` that starts the line number. It is url-encoded at evaluation time, so
 * it is decoded back before use. The nested `at eval (eval at <anonymous> (plugin:foo), <anonymous>:1:56)`
 * shape a plugin's own `eval` produces matches the same way, since the id still follows the marker.
 *
 * `/` ends the id as well, so the source-map-rewritten form `app://obsidian.md/plugin:<id>/src/foo.ts:1:2`
 * — which `obsidian-dev-utils` emits and a stack-mapping tool can surface — yields the id alone rather than
 * the id plus a path. No id can contain a `/` regardless: `encodeURIComponent` would have escaped it.
 */
const PLUGIN_FRAME_REG_EXP = /\bplugin:[^:)\s/]+/g;

/**
 * The marker each match starts with, sliced back off to leave the id.
 */
const PLUGIN_FRAME_PREFIX = 'plugin:';

/**
 * How deep to look for the plugin frame.
 *
 * `Error.stackTraceLimit` defaults to 10, which a bundled plugin calling through its own helpers and a
 * library before reaching the vault can outrun. Raised only around the capture and restored straight
 * after, so nothing else in the app pays for it.
 */
const STACK_TRACE_LIMIT = 50;

/**
 * Captures the current call stack with enough frames to reach the calling plugin.
 *
 * The capture itself is `obsidian-dev-utils`' {@link getStackTrace}; the only thing added here is the
 * raised frame limit, which that helper does not touch.
 *
 * @returns The stack trace.
 */
export function captureStackTrace(): string {
  const originalStackTraceLimit = Error.stackTraceLimit;
  Error.stackTraceLimit = STACK_TRACE_LIMIT;
  try {
    return getStackTrace();
  } finally {
    Error.stackTraceLimit = originalStackTraceLimit;
  }
}

/**
 * Finds the community plugin nearest to the top of `stack`, ignoring this plugin's own frames.
 *
 * This plugin's frames are always present — the capture itself happens inside a patch this plugin
 * installed — so skipping `ownPluginId` is what makes the FIRST remaining match the actual caller. When a
 * plugin reaches the vault through another plugin's API, the nearest frame is the one that performed the
 * write, which is the plugin the user would name.
 *
 * @param stack - A stack trace, as produced by {@link captureStackTrace}.
 * @param ownPluginId - This plugin's `manifest.id`, whose frames are skipped.
 * @returns The creating plugin's id, or `null` when no foreign plugin frame is present.
 */
export function findCreatingPluginId(stack: string, ownPluginId: string): null | string {
  for (const pluginFrame of stack.match(PLUGIN_FRAME_REG_EXP) ?? []) {
    const pluginId = decodePluginId(pluginFrame.slice(PLUGIN_FRAME_PREFIX.length));
    if (pluginId !== ownPluginId) {
      return pluginId;
    }
  }

  return null;
}

/**
 * Reverses the `encodeURIComponent` Obsidian applies when it builds the source URL.
 *
 * A malformed sequence is impossible from Obsidian's own encoder, but the stack is untrusted text, and a
 * throwing decode here would abort a vault write.
 *
 * @param encodedPluginId - The id as it appears in the frame.
 * @returns The decoded id, or the raw text when it does not decode.
 */
function decodePluginId(encodedPluginId: string): string {
  try {
    return decodeURIComponent(encodedPluginId);
  } catch {
    return encodedPluginId;
  }
}
