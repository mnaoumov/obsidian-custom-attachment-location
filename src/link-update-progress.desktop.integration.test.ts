import { registerLinkUpdateProgressSuite } from './link-update-progress-shared.integration.test.ts';

// Desktop-only: no Android emulator is available in this environment. The rename/link-update flow is
// Cross-platform, so this can be lifted to Android by adding a thin `*.android.integration.test.ts`
// Entry point that calls the same shared suite.
registerLinkUpdateProgressSuite('desktop');
