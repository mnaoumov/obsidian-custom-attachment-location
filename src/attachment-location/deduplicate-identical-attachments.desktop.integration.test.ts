import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for discussion #96: with `Deduplicate identical attachments` on, collecting the
 * same attachment twice must leave ONE file, with every reference pointing at it.
 *
 * The reporter's own case is staged: two notes in different folders each hold a copy of the same image
 * under the same name, and both collect into one shared folder. The first copy moves in. The second finds
 * the destination taken by identical bytes, so its note is pointed at the first and it goes to the trash.
 * A canvas that also embeds the second copy is rewritten by the vault-wide scan, because Obsidian does not
 * index canvases into the metadata cache.
 *
 * A control phase stages different bytes under the same name and must still get the duplicate-name
 * suffix, since a name match alone never merges. A third phase collects a CANVAS whose own file node
 * holds the duplicate, which the collector rewrites itself.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
/*
 * Under the transport's ~30s per-closure cap, which the closure's ten waits share. Each one is an index
 * update or a queued collect in a small temp vault, well under a second.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 2500;

interface CanvasPhaseResult {
  readonly fileNodePath: null | string;
}

interface ControlPhaseResult {
  readonly secondLinkTarget: null | string;
  readonly sharedFolderFiles: string[];
}

interface FixPhaseResult {
  readonly firstLinkTarget: null | string;
  readonly otherCanvasFileNodePath: null | string;
  readonly secondLinkTarget: null | string;
  readonly sharedFolderFiles: string[];
}

interface ProbeResult {
  readonly canvasPhase: CanvasPhaseResult;
  readonly control: ControlPhaseResult;
  readonly fix: FixPhaseResult;
  readonly probesFound: boolean;
}

describe('Deduplicate identical attachments (discussion #96)', () => {
  it('keeps one file for the same attachment collected twice, and still suffixes different bytes', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        findPluginSettingsComponent: findSettingsComponent,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface DeduplicateSettings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          collectAttachmentUsedByMultipleNotesMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldDeduplicateIdenticalAttachments: boolean;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldFollowObsidianAttachmentLocation: boolean;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          shouldRenameCollectedAttachments: boolean;
        }

        interface CanvasData {
          readonly nodes: CanvasNode[];
        }

        interface CanvasNode {
          readonly file?: string;
        }

        type CollectAttachmentsInAbstractFilesFunction = (this: unknown, abstractFiles: unknown[]) => void;

        function isDeduplicateSettings(value: unknown): value is DeduplicateSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['collectAttachmentUsedByMultipleNotesMode'] === 'string'
            && typeof record['shouldDeduplicateIdenticalAttachments'] === 'boolean'
            && typeof record['shouldFollowObsidianAttachmentLocation'] === 'boolean'
            && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
        }

        const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;
        const foundSettingsComponent = findSettingsComponent(pluginRecord, isDeduplicateSettings);
        const foundCollect = pluginRecord?.['collectAttachmentsInAbstractFiles'];
        if (!foundSettingsComponent || typeof foundCollect !== 'function') {
          return {
            canvasPhase: { fileNodePath: null },
            control: { secondLinkTarget: null, sharedFolderFiles: [] },
            fix: { firstLinkTarget: null, otherCanvasFileNodePath: null, secondLinkTarget: null, sharedFolderFiles: [] },
            probesFound: false
          };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settingsComponent = foundSettingsComponent;
        const collectAttachmentsInAbstractFiles = foundCollect as CollectAttachmentsInAbstractFilesFunction;

        const priorSettings = { ...settingsComponent.settings };
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const sharedFolderPath = `dd-shared-${stamp}`;
        const createdPaths: string[] = [];

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone: the collect moves and
         * trashes entries on its own queue, and trashing one a second time throws `ENOENT`.
         */
        async function trashIfExists(path: string): Promise<void> {
          const existing = app.vault.getAbstractFileByPath(path);
          if (!existing) {
            return;
          }
          try {
            await app.fileManager.trashFile(existing);
          } catch {
            // Removed between the lookup and the trash, which is the outcome this wanted anyway.
          }
        }

        async function createImage(folderPath: string, bytes: number[]): Promise<string> {
          if (!app.vault.getFolderByPath(folderPath)) {
            await app.vault.createFolder(folderPath);
            createdPaths.push(folderPath);
          }
          const imagePath = `${folderPath}/img.png`;
          await app.vault.createBinary(imagePath, new Uint8Array(bytes).buffer);
          return imagePath;
        }

        async function createNote(notePath: string, imagePath: string): Promise<void> {
          await app.vault.create(notePath, `![[${imagePath}]]\n`);
          createdPaths.push(notePath);
          // The embed must be indexed, or the collector walks a note with no links and moves nothing.
          await waitUntil({
            message: `the embed in ${notePath} was not indexed`,
            predicate: () => app.metadataCache.resolvedLinks[notePath]?.[imagePath] !== undefined,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
        }

        async function createCanvas(canvasPath: string, imagePath: string): Promise<void> {
          await app.vault.create(
            canvasPath,
            JSON.stringify({
              edges: [],
              nodes: [{ file: imagePath, height: 100, id: 'n1', type: 'file', width: 100, x: 0, y: 0 }]
            })
          );
          createdPaths.push(canvasPath);
        }

        // Waiting for the incoming copy to leave its folder is what proves the collect ran at all.
        async function collect(notePath: string, incomingImagePath: string): Promise<void> {
          collectAttachmentsInAbstractFiles.call(pluginRecord, [app.vault.getFileByPath(notePath)]);
          await waitUntil({
            message: `${incomingImagePath} never left its folder, so the collect of ${notePath} did not run`,
            predicate: () => app.vault.getFileByPath(incomingImagePath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
        }

        function getLinkTarget(notePath: string): null | string {
          const embed = app.metadataCache.getCache(notePath)?.embeds?.[0];
          return embed ? app.metadataCache.getFirstLinkpathDest(embed.link, notePath)?.path ?? null : null;
        }

        async function getCanvasFileNodePath(canvasPath: string): Promise<null | string> {
          const canvasFile = app.vault.getFileByPath(canvasPath);
          if (!canvasFile) {
            return null;
          }
          const data = JSON.parse(await app.vault.read(canvasFile)) as CanvasData;
          return data.nodes[0]?.file ?? null;
        }

        function getSharedFolderFiles(): string[] {
          return app.vault.getFiles().map((file) => file.path).filter((path) => path.startsWith(`${sharedFolderPath}/`)).sort();
        }

        async function waitForLinkTarget(notePath: string, expectedPath: string): Promise<void> {
          await waitUntil({
            message: `${notePath} was not repointed at ${expectedPath}`,
            predicate: () => getLinkTarget(notePath) === expectedPath,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
        }

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = sharedFolderPath;
            // The canvas below is a second referrer, and Move is the mode that carries every referrer along.
            settings.collectAttachmentUsedByMultipleNotesMode = 'Move';
            settings.shouldDeduplicateIdenticalAttachments = true;
            settings.shouldFollowObsidianAttachmentLocation = false;
            // The name must survive the collect, or two copies would never meet at one destination.
            settings.shouldRenameCollectedAttachments = false;
          });
          createdPaths.push(sharedFolderPath);

          // Fix: the same bytes under the same name, from two notes.
          const firstImagePath = await createImage(`dd-a-${stamp}`, [1, 2, 3, 4]);
          const secondImagePath = await createImage(`dd-b-${stamp}`, [1, 2, 3, 4]);
          const firstNotePath = `dd-a-${stamp}.md`;
          const secondNotePath = `dd-b-${stamp}.md`;
          const otherCanvasPath = `dd-board-${stamp}.canvas`;
          await createNote(firstNotePath, firstImagePath);
          await createNote(secondNotePath, secondImagePath);
          await createCanvas(otherCanvasPath, secondImagePath);

          await collect(firstNotePath, firstImagePath);
          await collect(secondNotePath, secondImagePath);
          const mergedPath = `${sharedFolderPath}/img.png`;
          await waitForLinkTarget(secondNotePath, mergedPath);
          const fix: FixPhaseResult = {
            firstLinkTarget: getLinkTarget(firstNotePath),
            otherCanvasFileNodePath: await getCanvasFileNodePath(otherCanvasPath),
            secondLinkTarget: getLinkTarget(secondNotePath),
            sharedFolderFiles: getSharedFolderFiles()
          };

          // Control: the same name, different bytes - the suffix, as without the setting.
          const differentImagePath = await createImage(`dd-c-${stamp}`, [9, 9, 9, 9]);
          const differentNotePath = `dd-c-${stamp}.md`;
          await createNote(differentNotePath, differentImagePath);
          await collect(differentNotePath, differentImagePath);
          await waitForLinkTarget(differentNotePath, `${sharedFolderPath}/img 1.png`);
          const control: ControlPhaseResult = {
            secondLinkTarget: getLinkTarget(differentNotePath),
            sharedFolderFiles: getSharedFolderFiles()
          };

          // A canvas collected from: its own file node holds the duplicate, and the collector rewrites it.
          const canvasImagePath = await createImage(`dd-d-${stamp}`, [1, 2, 3, 4]);
          const collectedCanvasPath = `dd-d-${stamp}.canvas`;
          await createCanvas(collectedCanvasPath, canvasImagePath);
          await collect(collectedCanvasPath, canvasImagePath);
          await waitUntil({
            message: 'the collected canvas was not repointed',
            predicate: async () => await getCanvasFileNodePath(collectedCanvasPath) === mergedPath,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          const canvasPhase: CanvasPhaseResult = {
            fileNodePath: await getCanvasFileNodePath(collectedCanvasPath)
          };

          return { canvasPhase, control, fix, probesFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorSettings.attachmentFolderPath;
            settings.collectAttachmentUsedByMultipleNotesMode = priorSettings.collectAttachmentUsedByMultipleNotesMode;
            settings.shouldDeduplicateIdenticalAttachments = priorSettings.shouldDeduplicateIdenticalAttachments;
            settings.shouldFollowObsidianAttachmentLocation = priorSettings.shouldFollowObsidianAttachmentLocation;
            settings.shouldRenameCollectedAttachments = priorSettings.shouldRenameCollectedAttachments;
          });
          for (const path of createdPaths.reverse()) {
            await trashIfExists(path);
          }
        }
      },
      input: {
        findPluginSettingsComponent,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // Fix: one file is left, and both notes and the other canvas point at it.
    expect(result.fix.sharedFolderFiles).toEqual([expect.stringMatching(/^dd-shared-.*\/img\.png$/)]);
    expect(result.fix.firstLinkTarget).toBe(result.fix.sharedFolderFiles[0]);
    expect(result.fix.secondLinkTarget).toBe(result.fix.sharedFolderFiles[0]);
    expect(result.fix.otherCanvasFileNodePath).toBe(result.fix.sharedFolderFiles[0]);

    // Control: different bytes keep the suffix.
    expect(result.control.sharedFolderFiles).toEqual([
      expect.stringMatching(/^dd-shared-.*\/img 1\.png$/),
      expect.stringMatching(/^dd-shared-.*\/img\.png$/)
    ]);
    expect(result.control.secondLinkTarget).toBe(result.control.sharedFolderFiles[0]);

    // A collected canvas's own file node follows the merge too.
    expect(result.canvasPhase.fileNodePath).toBe(result.fix.sharedFolderFiles[0]);
  }, 180_000);
});
