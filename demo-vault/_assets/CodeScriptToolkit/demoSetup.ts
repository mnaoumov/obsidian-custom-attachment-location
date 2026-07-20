import type { App } from 'obsidian';

import { Notice } from 'obsidian';
import {
  enableCommunityPlugin,
  installCommunityPlugin
} from 'obsidian-dev-utils/obsidian/community-plugins';

// Custom Attachment Location works by intercepting how Obsidian saves attachments, driven entirely by
// Its settings - so there is nothing for a code-button to drive; the demo notes ask you to paste or drag a
// File and observe where it lands. The only helper the vault needs is the shared CodeScript Toolkit installer
// Used by the prerequisite note's button.
export async function installAndEnable(app: App, pluginId: string): Promise<void> {
  await installCommunityPlugin({ app, pluginId });
  await enableCommunityPlugin({ app, pluginId });
  new Notice(`Installed and enabled: ${pluginId}`);
}
