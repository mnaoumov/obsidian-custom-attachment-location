import { registerLinkDisplayTextSuite } from './link-display-text-shared.integration.test.ts';

// Desktop-only: no Android emulator is available in this environment. The `generateMarkdownLink`
// Patch is cross-platform, so an Android entry point can call the same shared suite later.
registerLinkDisplayTextSuite('desktop');
