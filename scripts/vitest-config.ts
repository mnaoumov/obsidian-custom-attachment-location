import type { ObsidianPluginVitestConfigContext } from 'obsidian-dev-utils/script-utils/test-runners/vitest-config';
import type { TestProjectConfiguration } from 'vitest/config';

import { defineObsidianPluginVitestConfig } from 'obsidian-dev-utils/script-utils/test-runners/vitest-config';

/**
 * The screenshot-capture suites (T461-P21) that write
 * `images/screenshots/screenshot-*.png`.
 *
 * They are named `*.desktop-capture.` / `*.android-capture.` rather than
 * `*.desktop.` / `*.android.` so they match NONE of the standard project globs.
 * That keeps them out of `npm run test:integration` entirely — capturing is an
 * explicit operation (`npm run capture:screenshots`), not something every test
 * run does. Folding them into the standard projects would rewrite ten PNGs on
 * every run and dirty the tree mid-release.
 */
const DESKTOP_CAPTURE_TEST_FILES = 'src/**/*.desktop-capture.integration.test.ts';
const ANDROID_CAPTURE_TEST_FILES = 'src/**/*.android-capture.integration.test.ts';

/**
 * The AVD the mobile shots are taken on: 900x1600 at density 320, which is
 * exactly the size the community store asks for, so the capture needs no crop,
 * no rescale and no letterbox. The shared `obsidian_test` AVD is a Pixel 10 Pro
 * XL at 1344x2994 (~9:20) and cannot produce it; resizing that one at runtime
 * destroys the Appium session, because the display change recreates the
 * activity and with it the WebView the session is attached to.
 *
 * Needs one-time provisioning — see [[T461-P21]].
 */
const SCREENSHOT_AVD_NAME = 'obsidian_screenshots';

const APPIUM_URL = 'http://localhost:4723';

/**
 * This AVD is cold-booted and rarely used, so Obsidian's first layout on it is
 * far slower than on the well-warmed shared one; the 90s default expires while
 * it is still starting up.
 */
const LAYOUT_READY_TIMEOUT_IN_MILLISECONDS = 240_000;

/**
 * The demo-vault button suite. It drives a real desktop Obsidian like the desktop project, but opens
 * a copy of the in-repo `demo-vault/` rather than an empty vault — hence its own `globalSetup` — and
 * needs its own suffix so the desktop project does not also collect it and open it against a vault
 * with no notes in it.
 */
const DEMO_VAULT_TEST_FILES = 'src/**/*.demo-vault.integration.test.ts';

/**
 * One `it` per note runs every button in that note, and each button re-opens the note, walks the
 * preview to find itself and then waits up to 15s for a result. A note with a dozen buttons therefore
 * blows well past the desktop project's 30s default — which fails the whole note with a bare vitest
 * timeout instead of naming the button that actually misbehaved.
 */
const DEMO_VAULT_TIMEOUT_IN_MILLISECONDS = 600_000;

/**
 * Empties the shared vault after each `integration-tests:desktop` file, so a late file does not inherit
 * everything the ~30 before it created. See the file's own header for why that matters.
 */
const DESKTOP_VAULT_CLEANUP_SETUP_FILE = './scripts/vitest-setup-desktop-vault-cleanup.ts';

/**
 * The desktop transport's per-command budget.
 *
 * A whole `evalInObsidian` callback is ONE `Runtime.evaluate`, so this bounds the entire staging +
 * waiting + assertion sequence a suite performs inside Obsidian — not a single round trip. The default
 * is the project's own 30s test budget, which silently truncates the suites that raise their per-test
 * timeout (`it(..., 180_000)`) to do real work: they were killed at 30s by the transport while vitest
 * was still happily waiting, and reported as `CDP command timed out ... Runtime.evaluate`, naming
 * neither the suite's `waitUntil` message nor the assertion.
 *
 * Set above the largest per-test budget in the suite so vitest — which knows what was being awaited —
 * always reports the overrun. Nothing hangs longer as a result: vitest's own timeout is the backstop.
 */
const CDP_COMMAND_TIMEOUT_IN_MILLISECONDS = 240_000;

/**
 * The desktop project's `setupFiles` without the vault cleanup.
 *
 * `editContext` runs BEFORE `customProjects`, and the projects below spread the very same
 * `context.desktop` object — without dropping it again they would inherit a cleanup that empties the
 * vault whose contents are their fixture.
 *
 * @param context - The context the library hands over.
 * @returns The setup files with the cleanup removed.
 */
function setupFilesWithoutVaultCleanup(context: ObsidianPluginVitestConfigContext): string[] {
  return toSetupFileList(context.desktop.setupFiles).filter((setupFile) => setupFile !== DESKTOP_VAULT_CLEANUP_SETUP_FILE);
}

/**
 * Normalizes `setupFiles`, which is `string | string[] | undefined` in vitest's own type.
 *
 * @param setupFiles - The value to normalize.
 * @returns The value as an array.
 */
function toSetupFileList(setupFiles: string | string[] | undefined): string[] {
  return [setupFiles ?? []].flat();
}

export const config = defineObsidianPluginVitestConfig({
  customProjects(context: ObsidianPluginVitestConfigContext): TestProjectConfiguration[] {
    return [
      {
        test: {
          ...context.desktop,
          include: [DESKTOP_CAPTURE_TEST_FILES],
          name: 'capture-screenshots:desktop',
          setupFiles: setupFilesWithoutVaultCleanup(context)
        }
      },
      {
        test: {
          ...context.android,
          environmentOptions: {
            obsidianTransport: {
              appiumUrl: APPIUM_URL,
              avdName: SCREENSHOT_AVD_NAME,
              layoutReadyTimeoutInMilliseconds: LAYOUT_READY_TIMEOUT_IN_MILLISECONDS,
              type: 'obsidian-android-appium'
            }
          },
          include: [ANDROID_CAPTURE_TEST_FILES],
          name: 'capture-screenshots:android'
        }
      },
      {
        test: {
          ...context.desktop,
          globalSetup: ['./scripts/demo-vault-global-setup.ts'],
          include: [DEMO_VAULT_TEST_FILES],
          name: 'integration-tests:demo-vault',
          setupFiles: setupFilesWithoutVaultCleanup(context),
          testTimeout: DEMO_VAULT_TIMEOUT_IN_MILLISECONDS
        }
      }
    ];
  },
  editContext(context: ObsidianPluginVitestConfigContext): void {
    context.desktop.setupFiles = [...toSetupFileList(context.desktop.setupFiles), DESKTOP_VAULT_CLEANUP_SETUP_FILE];

    context.desktop.environmentOptions = {
      obsidianTransport: {
        commandTimeoutInMilliseconds: CDP_COMMAND_TIMEOUT_IN_MILLISECONDS,
        type: 'obsidian-cdp'
      }
    };

    context.desktopPerformance.environmentOptions = {
      /*
       * The bottleneck closure holds a single `Runtime.evaluate` open for the whole
       * index-wait + settle + benchmark run, which far exceeds the transport's default
       * 30s per-command timeout, so raise it to the performance test budget.
       */
      obsidianTransport: {
        commandTimeoutInMilliseconds: context.performanceTimeoutInMilliseconds,
        type: 'obsidian-cdp'
      }
    };

    /*
     * The performance vault is pre-populated with hundreds of notes embedding binary
     * attachments before open, which the shared global setup knows nothing about.
     */
    context.desktopPerformance.globalSetup = ['./scripts/vitest-global-setup-performance.ts'];
  }
});
