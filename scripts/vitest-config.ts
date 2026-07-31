import { defineObsidianPluginVitestConfig } from 'obsidian-dev-utils/script-utils/test-runners/vitest-config';

export const config = defineObsidianPluginVitestConfig({
  editContext(context) {
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
