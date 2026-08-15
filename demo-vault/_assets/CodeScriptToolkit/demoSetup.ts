import type { App } from 'obsidian';

import { Notice } from 'obsidian';
import { configureCommunityPlugin } from 'obsidian-dev-utils/obsidian/community-plugins';

const PLUGIN_ID = 'custom-attachment-location';

interface DemoSettingsPatch {
  attachmentFolderPath?: string;
  generatedAttachmentFileName?: string;
  shouldRenameAttachmentFiles?: boolean;
}

/**
 * Reports where an attachment pasted into the ACTIVE note would be saved, right now, with the current
 * settings.
 *
 * Pasting cannot be automated — the image has to come from your clipboard — but the answer the plugin
 * would give can be asked for directly: it patches `vault.getAvailablePathForAttachments`, which is
 * exactly what Obsidian calls when a paste happens. So a token pattern can be inspected without
 * finding an image first, and without waiting to see where the file ends up.
 *
 * Manual equivalent: paste an image into the note and look at where it landed in the File Explorer.
 */
export async function previewAttachmentPath(app: App): Promise<void> {
  const activeFile = app.workspace.getActiveFile();
  if (!activeFile) {
    new Notice('Open a note first — the path depends on which note you are in.');
    return;
  }

  const path = await app.vault.getAvailablePathForAttachments('pasted-image', 'png', activeFile);
  new Notice(`A pasted image would be saved as:\n${path}`, 10_000);
}

/**
 * Applies a settings patch, live, through the plugin's own settings component.
 *
 * Manual equivalent: edit the same field in **Settings -> Community plugins -> Custom Attachment
 * Location**.
 */
export async function changeSettings(app: App, patch: DemoSettingsPatch): Promise<void> {
  await configureCommunityPlugin({ app, pluginId: PLUGIN_ID, settings: patch });
  new Notice('Applied. Ask where a paste would go to see the effect.');
}

/**
 * Restores the two patterns this vault ships with.
 *
 * Manual equivalent: set **Location for new attachments** back to `./assets/${noteFileName}` and the
 * generated file name back to its default.
 */
export async function restoreDefaultPatterns(app: App): Promise<void> {
  await changeSettings(app, {
    attachmentFolderPath: './assets/${noteFileName}',
    generatedAttachmentFileName: 'file-${date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}'
  });
}
