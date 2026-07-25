import { registerClipboardImageRenameSuite } from './clipboard-image-rename-shared.integration.test.ts';

// Desktop-only: no Android emulator is available in this environment. The clipboard `insertFiles`
// Rename path is cross-platform, so an Android entry point can call the same shared suite later.
registerClipboardImageRenameSuite('desktop');
