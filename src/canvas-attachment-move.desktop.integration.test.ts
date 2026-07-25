import { registerCanvasAttachmentMoveSuite } from './canvas-attachment-move-shared.integration.test.ts';

// Desktop-only: no Android emulator is available in this environment. Canvas rename/attachment-move
// Is cross-platform, so an Android entry point can call the same shared suite when an emulator exists.
registerCanvasAttachmentMoveSuite('desktop');
