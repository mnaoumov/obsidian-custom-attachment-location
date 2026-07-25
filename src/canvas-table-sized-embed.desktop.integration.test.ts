import { registerCanvasTableSizedEmbedSuite } from './canvas-table-sized-embed-shared.integration.test.ts';

// Desktop-only: no Android emulator is available in this environment. The canvas rewrite path is
// Cross-platform, so an Android entry point can call the same shared suite when an emulator exists.
registerCanvasTableSizedEmbedSuite('desktop');
