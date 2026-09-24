import type { Server } from 'node:http';

import { createServer } from 'node:http';
import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  afterAll,
  beforeAll,
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for issue #50: a network image downloaded by "Collect attachments in current file"
 * must be linked through Obsidian's own link generator, exactly like a pasted attachment, so it honors
 * "New link format" and gets a properly escaped destination.
 *
 * The note lives in a folder whose name contains a space, which is what made the old behavior visibly
 * wrong: it wrote the vault-relative save path verbatim, producing
 * `![Diagram](Research Notes/assets/...)` - both absolute and unescaped - instead of the relative
 * `![Diagram](assets/...)` that a pasted attachment produces.
 *
 * The image is served from a local HTTP server so the test never depends on an external host.
 */

const PNG_BYTES = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
const TEST_TIMEOUT_IN_MILLISECONDS = 120_000;

interface ProbeResult {
  readonly content: string;
  readonly downloadedPaths: readonly string[];
  readonly settingsFound: boolean;
}

let imageUrl: string;
let server: Server;

beforeAll(async () => {
  server = createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'image/png' });
    response.end(PNG_BYTES);
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  imageUrl = `http://127.0.0.1:${String(port)}/diagram.png`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
});

describe('Network image link format (issue #50)', () => {
  it('should link a downloaded network image through Obsidian link generation', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        findPluginSettingsComponent: findSettingsComponent,
        imageUrl: url,
        lib: { waitUntil }
      }): Promise<ProbeResult> {
        interface NetworkImageSettings {
          attachmentFolderPath: string;
          downloadNetworkImages: boolean;
        }

        function isNetworkImageSettings(value: unknown): value is NetworkImageSettings {
          if (typeof value !== 'object' || value === null) {
            return false;
          }
          const record = value as Record<string, unknown>;
          return typeof record['downloadNetworkImages'] === 'boolean' && typeof record['attachmentFolderPath'] === 'string';
        }

        const settingsComponent = findSettingsComponent(
          app.plugins.getPlugin('obsidian-custom-attachment-location'),
          isNetworkImageSettings
        );
        if (!settingsComponent) {
          return { content: '', downloadedPaths: [], settingsFound: false };
        }

        // The temp vault is shared by every suite in this project, so each mutated setting has to be put back
        // afterwards - otherwise this test silently reconfigures link generation for the tests that follow.
        const didDownloadNetworkImages = settingsComponent.settings.downloadNetworkImages;
        const originalAttachmentFolderPath = settingsComponent.settings.attachmentFolderPath;
        const originalUseMarkdownLinks = app.vault.getConfig('useMarkdownLinks');
        const originalNewLinkFormat = app.vault.getConfig('newLinkFormat');

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.downloadNetworkImages = true;
            settings.attachmentFolderPath = './assets';
          });

          // The exact configuration from the report: markdown links, relative to the note.
          app.vault.setConfig('useMarkdownLinks', true);
          app.vault.setConfig('newLinkFormat', 'relative');

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const folderPath = `Research Notes ${stamp}`;
          const notePath = `${folderPath}/article.md`;

          await app.vault.createFolder(folderPath);
          const note = await app.vault.create(notePath, `![Diagram](${url})`);

          await app.workspace.getLeaf(false).openFile(note);

          /*
           * The collect command reads the ACTIVE file, and `openFile` resolves before the workspace has
           * Finished switching. Firing it too early collects nothing, and the poll below then simply
           * Runs out — burning the entire test budget for a command that never ran.
           */
          await waitUntil({
            message: 'the staged note never became the active file',
            predicate: () => app.workspace.getActiveFile()?.path === note.path,
            timeoutInMilliseconds: 5000
          });

          app.commands.executeCommandById('obsidian-custom-attachment-location:collect-attachments-in-file');

          /*
           * The download and rewrite run on an internal queue; poll until the note no longer holds the
           * Network URL. With the wait above, this closure declares ~20s, under the transport's ~30s
           * Per-closure default: the project's raised command timeout is a backstop, not a budget, and a
           * Closure that spends it dies as a bare transport timeout rather than as the wait that overran.
           * The image is served from localhost, so the rewrite lands within moments.
           */
          const deadline = Date.now() + 15_000;
          let content = await app.vault.read(note);
          while (Date.now() < deadline && content.includes(url)) {
            await sleep(200);
            content = await app.vault.read(note);
          }

          const downloadedPaths = app.vault.getFiles()
            .map((file) => file.path)
            .filter((path) => path.startsWith(`${folderPath}/`) && path !== notePath);

          return { content, downloadedPaths, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.downloadNetworkImages = didDownloadNetworkImages;
            settings.attachmentFolderPath = originalAttachmentFolderPath;
          });
          app.vault.setConfig('useMarkdownLinks', originalUseMarkdownLinks);
          app.vault.setConfig('newLinkFormat', originalNewLinkFormat);
        }
      },
      input: { findPluginSettingsComponent, imageUrl },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // The image really was downloaded into the note's own `assets` folder.
    expect(result.downloadedPaths).toHaveLength(1);
    expect(result.downloadedPaths[0]).toMatch(/^Research Notes .*\/assets\/.*\.png$/);

    // It is still an embed, the alt text survived, and the destination is relative to the note rather than
    // the vault-relative save path the old code wrote verbatim.
    expect(result.content).toMatch(/^!\[Diagram]\(assets\/\S+\.png\)$/);
    expect(result.content).not.toContain('Research Notes');
    expect(result.content).not.toContain(' ');
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});
