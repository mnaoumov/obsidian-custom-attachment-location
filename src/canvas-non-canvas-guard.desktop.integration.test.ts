import { registerCanvasNonCanvasGuardSuite } from './canvas-non-canvas-guard-shared.integration.test.ts';

// Desktop-only: no Android emulator is available in this environment. The canvas guard is
// Cross-platform, so an Android entry point can call the same shared suite when an emulator exists.
registerCanvasNonCanvasGuardSuite('desktop');
