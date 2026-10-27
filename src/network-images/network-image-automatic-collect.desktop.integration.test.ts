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

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * Issue #15 asked for a network image to be made local the moment its link lands in a note, with no command.
 * `Download network images` runs at the end of every collect, and `Collect attachments automatically` runs a
 * collect on every metadata change, so the two together are meant to answer it. This pins that combination.
 *
 * The note starts with NO local attachment, so the collect has nothing of its own to move and must still reach
 * the download step. The link is added with `vault.modify`, which is what an editor paste ends in, and no
 * command is run.
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
  imageUrl = `http://127.0.0.1:${String(port)}/photo.png`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => {
    server.close(() => {
      resolve();
    });
  });
});

describe('Network image downloaded by the automatic collect (issue #15)', () => {
  it('should make a network image added to a note local with no command run', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        findPluginSettingsComponent: findSettingsComponent,
        imageUrl: url
      }): Promise<ProbeResult> {
        interface AutomaticDownloadSettings {
          attachmentFolderPath: string;
          downloadNetworkImages: boolean;
          shouldCollectAttachmentsAutomatically: boolean;
        }

        function isAutomaticDownloadSettings(value: unknown): value is AutomaticDownloadSettings {
          if (typeof value !== 'object' || value === null) {
            return false;
          }
          const record = value as Record<string, unknown>;
          return typeof record['downloadNetworkImages'] === 'boolean'
            && typeof record['shouldCollectAttachmentsAutomatically'] === 'boolean'
            && typeof record['attachmentFolderPath'] === 'string';
        }

        const settingsComponent = findSettingsComponent(
          app.plugins.getPlugin('obsidian-custom-attachment-location'),
          isAutomaticDownloadSettings
        );
        if (!settingsComponent) {
          return { content: '', downloadedPaths: [], settingsFound: false };
        }

        // The temp vault is shared by every suite in this project, so each mutated setting is put back afterwards.
        const didDownloadNetworkImages = settingsComponent.settings.downloadNetworkImages;
        const didCollectAttachmentsAutomatically = settingsComponent.settings.shouldCollectAttachmentsAutomatically;
        const originalAttachmentFolderPath = settingsComponent.settings.attachmentFolderPath;

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.downloadNetworkImages = true;
            settings.shouldCollectAttachmentsAutomatically = true;
            settings.attachmentFolderPath = './assets';
          });

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const folderPath = `Automatic download ${stamp}`;
          const notePath = `${folderPath}/article.md`;

          await app.vault.createFolder(folderPath);
          const note = await app.vault.create(notePath, 'Some text.\n');

          await app.vault.modify(note, `Some text.\n\n![](${url})\n`);

          // The automatic collect runs on an internal queue once the metadata cache catches up; poll for the rewrite.
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
            settings.shouldCollectAttachmentsAutomatically = didCollectAttachmentsAutomatically;
            settings.attachmentFolderPath = originalAttachmentFolderPath;
          });
        }
      },
      input: { findPluginSettingsComponent, imageUrl },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // The image was downloaded into the note's own `assets` folder, and the note now links to it instead of the URL.
    expect(result.downloadedPaths).toHaveLength(1);
    expect(result.downloadedPaths[0]).toMatch(/^Automatic download .*\/assets\/.*\.png$/);
    expect(result.content).not.toContain(imageUrl);
    expect(result.content).toContain('.png');
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});
