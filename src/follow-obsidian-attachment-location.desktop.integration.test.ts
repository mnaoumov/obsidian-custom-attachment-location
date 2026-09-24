import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for the mode that follows Obsidian's own *Default location for new attachments*.
 *
 * Unit tests cannot prove the part that matters: the defect this mode invites is a LOOP, where the
 * `getConfig('attachmentFolderPath')` patch hands Obsidian a folder resolved from Obsidian's own setting back
 * as that setting. Only a real Obsidian, with a real note open, runs the patch and the resolver together.
 *
 * The expected folders are written out by hand rather than read off Obsidian with the plugin disabled: the
 * plugin cannot be disabled mid-run in the shared instance, and a hand-written table is an oracle that does
 * not share code with the thing it checks. It is Obsidian's documented behavior for each of the four options
 * on the *Files and links* page, for a note two folders deep.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
// Under the transport's ~30s per-closure cap; every wait below is a vault write or an index in a small vault.
const WAIT_TIMEOUT_IN_MILLISECONDS = 6000;
const SETTLE_TIMEOUT_IN_MILLISECONDS = 600;

interface CoreTabRow {
  readonly description: string;
  readonly hasButton: boolean;
  readonly hasDropdown: boolean;
  readonly name: string;
}

interface CoreTabSnapshot {
  readonly activeTabIdAfterButtonClick: null | string;
  readonly rows: readonly CoreTabRow[];
}

interface ModeResult {
  readonly configuredPath: string;
  readonly folderPath: string;
}

interface ProbeResult {
  readonly collectedPath: null | string;
  readonly configWhileFollowing: unknown;
  readonly configWhileTemplating: unknown;
  readonly coreTabWhileFollowing: CoreTabSnapshot;
  readonly coreTabWhileTemplating: CoreTabSnapshot;
  readonly modes: readonly ModeResult[];
  readonly probesFound: boolean;
}

describe('Follow Obsidian attachment location', () => {
  it('places, collects and relabels exactly as Obsidian would', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        findPluginSettingsComponent: findSettingsComponent,
        lib: { waitUntil },
        pluginId,
        settleTimeoutInMilliseconds,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface FollowSettings {
          attachmentFolderPath: string;
          collectedAttachmentFolderPath: string;
          shouldFollowObsidianAttachmentLocation: boolean;
          shouldRenameCollectedAttachments: boolean;
        }

        type CollectAttachmentsInAbstractFilesFunction = (this: unknown, abstractFiles: unknown[]) => void;

        function isFollowSettings(value: unknown): value is FollowSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['collectedAttachmentFolderPath'] === 'string'
            && typeof record['shouldFollowObsidianAttachmentLocation'] === 'boolean'
            && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
        }

        const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;

        const emptySnapshot: CoreTabSnapshot = { activeTabIdAfterButtonClick: null, rows: [] };
        /*
         * Edits go through the settings component's `editAndSave` rather than onto the settings object: Obsidian
         * renders its own settings tab from definitions cached when the tab was last updated, and it is the save
         * event that refreshes them, exactly as a user toggling the setting would.
         */
        const foundSettingsComponent = findSettingsComponent(pluginRecord, isFollowSettings);
        const foundCollect = pluginRecord?.['collectAttachmentsInAbstractFiles'];
        if (!foundSettingsComponent || typeof foundCollect !== 'function') {
          return {
            collectedPath: null,
            configWhileFollowing: null,
            configWhileTemplating: null,
            coreTabWhileFollowing: emptySnapshot,
            coreTabWhileTemplating: emptySnapshot,
            modes: [],
            probesFound: false
          };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settingsComponent = foundSettingsComponent;

        async function editSettings(changes: Partial<FollowSettings>): Promise<void> {
          await settingsComponent.editAndSave((settings) => {
            Object.assign(settings, changes);
          });
        }
        const collectAttachmentsInAbstractFiles = foundCollect as CollectAttachmentsInAbstractFilesFunction;

        function text(el: Element | null): string {
          return (el?.textContent ?? '').trim();
        }

        async function snapshotCoreTab(): Promise<CoreTabSnapshot> {
          const setting = app.setting;
          setting.open();
          setting.openTabById('file');
          await sleep(settleTimeoutInMilliseconds);
          const rowEls = [...setting.modalEl.querySelectorAll<HTMLElement>(':scope .vertical-tab-content .setting-item')];
          const rows = rowEls.map((el) => ({
            description: text(el.querySelector(':scope .setting-item-description')),
            hasButton: el.querySelector(':scope .setting-item-control button') !== null,
            hasDropdown: el.querySelector(':scope .setting-item-control select') !== null,
            name: text(el.querySelector(':scope .setting-item-name'))
          }));

          let activeTabIdAfterButtonClick: null | string = null;
          const locationRow = rowEls.find((el) => text(el.querySelector(':scope .setting-item-name')) === 'Default location for new attachments');
          const button = locationRow?.querySelector<HTMLButtonElement>(':scope .setting-item-control button') ?? null;
          if (button) {
            button.click();
            await sleep(settleTimeoutInMilliseconds);
            activeTabIdAfterButtonClick = setting.activeTab?.id ?? null;
          }

          // Close what this opened: the suite shares one Obsidian instance with every other suite.
          setting.close();
          await sleep(settleTimeoutInMilliseconds);
          return { activeTabIdAfterButtonClick, rows };
        }

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

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const rootFolder = `foal-${stamp}`;
        const noteFolder = `${rootFolder}/notes/sub`;
        const notePath = `${noteFolder}/Note.md`;
        const sourceFolder = `${rootFolder}/source`;
        const imageFileName = `foal-img-${stamp}.png`;
        const imagePath = `${sourceFolder}/${imageFileName}`;

        const priorConfig = app.vault.getConfig('attachmentFolderPath');
        const priorSettings: FollowSettings = {
          attachmentFolderPath: settingsComponent.settings.attachmentFolderPath,
          collectedAttachmentFolderPath: settingsComponent.settings.collectedAttachmentFolderPath,
          shouldFollowObsidianAttachmentLocation: settingsComponent.settings.shouldFollowObsidianAttachmentLocation,
          shouldRenameCollectedAttachments: settingsComponent.settings.shouldRenameCollectedAttachments
        };
        const leaf = app.workspace.getLeaf(true);

        try {
          await app.vault.createFolder(noteFolder);
          await app.vault.createFolder(sourceFolder);
          await app.vault.createBinary(imagePath, new ArrayBuffer(4));
          const note = await app.vault.create(notePath, `![[${imageFileName}]]\n`);

          // The template mode first, with a note OPEN: that is what makes the plugin cache a folder for the
          // `getConfig` patch, so the loop has something to feed back.
          await editSettings({ attachmentFolderPath: './template-mode', shouldFollowObsidianAttachmentLocation: false });
          app.vault.setConfig('attachmentFolderPath', './attachments');
          await leaf.openFile(note);
          await waitUntil({
            message: 'the plugin never took over getConfig for the open note',
            predicate: () => app.vault.getConfig('attachmentFolderPath') !== './attachments',
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          const configWhileTemplating = app.vault.getConfig('attachmentFolderPath');
          const coreTabWhileTemplating = await snapshotCoreTab();

          await editSettings({ shouldFollowObsidianAttachmentLocation: true });
          // No wait beyond the save: the patch must stand aside the moment the mode is on, not at the next note switch.
          const configWhileFollowing = app.vault.getConfig('attachmentFolderPath');
          const coreTabWhileFollowing = await snapshotCoreTab();

          const modes: ModeResult[] = [];
          for (const configuredPath of ['/', 'assets', './', './attachments']) {
            app.vault.setConfig('attachmentFolderPath', configuredPath);
            const attachmentPath = await app.vault.getAvailablePathForAttachments(`foal-new-${stamp}`, 'png', note);
            const slashIndex = attachmentPath.lastIndexOf('/');
            modes.push({ configuredPath, folderPath: slashIndex === -1 ? '' : attachmentPath.slice(0, slashIndex) });
          }

          // Collect into Obsidian's location, under the name the file already has.
          app.vault.setConfig('attachmentFolderPath', './attachments');
          await editSettings({ collectedAttachmentFolderPath: '', shouldRenameCollectedAttachments: false });
          await waitUntil({
            message: 'the staged embed was not indexed',
            predicate: () => {
              const imageFile = app.vault.getFileByPath(imagePath);
              return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length > 0;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          collectAttachmentsInAbstractFiles.call(pluginRecord, [note]);
          await waitUntil({
            message: 'the staged attachment never left its source folder, so the collect did not run',
            predicate: () => app.vault.getFileByPath(imagePath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          const collectedPath = app.vault.getFiles().map((file) => file.path).find((path) => path.endsWith(`/${imageFileName}`)) ?? null;

          return {
            collectedPath,
            configWhileFollowing,
            configWhileTemplating,
            coreTabWhileFollowing,
            coreTabWhileTemplating,
            modes,
            probesFound: true
          };
        } finally {
          leaf.detach();
          await editSettings(priorSettings);
          app.vault.setConfig('attachmentFolderPath', priorConfig);
          for (const path of [rootFolder, 'assets', `foal-new-${stamp}.png`]) {
            await trashIfExists(path);
          }
        }
      },
      input: {
        findPluginSettingsComponent,
        pluginId: PLUGIN_ID,
        settleTimeoutInMilliseconds: SETTLE_TIMEOUT_IN_MILLISECONDS,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);

    // Template mode takes getConfig over (the control: without it the loop check below proves nothing).
    expect(result.configWhileTemplating).not.toBe('./attachments');
    // Follow mode hands Obsidian its own value back, untouched: no loop.
    expect(result.configWhileFollowing).toBe('./attachments');

    const [vaultRoot, fixedFolder, currentFolder, subfolder] = result.modes;
    expect(vaultRoot).toEqual({ configuredPath: '/', folderPath: '' });
    expect(fixedFolder).toEqual({ configuredPath: 'assets', folderPath: 'assets' });
    expect(currentFolder?.folderPath).toMatch(/^foal-[\d-]+\/notes\/sub$/);
    expect(subfolder?.folderPath).toMatch(/^foal-[\d-]+\/notes\/sub\/attachments$/);

    expect(result.collectedPath).toMatch(/^foal-[\d-]+\/notes\/sub\/attachments\/foal-img-[\d-]+\.png$/);

    // Template mode: Obsidian's row says who decides, links to the plugin, and its follow-up rows are gone.
    const templatingRow = result.coreTabWhileTemplating.rows.find((row) => row.name === 'Default location for new attachments');
    expect(templatingRow?.description).toContain('Controlled by Custom Attachment Location');
    expect(templatingRow?.hasButton).toBe(true);
    expect(templatingRow?.hasDropdown).toBe(false);
    expect(result.coreTabWhileTemplating.rows.map((row) => row.name)).not.toContain('Attachment folder path');
    expect(result.coreTabWhileTemplating.rows.map((row) => row.name)).not.toContain('Subfolder name');
    expect(result.coreTabWhileTemplating.activeTabIdAfterButtonClick).toBe(PLUGIN_ID);

    // Follow mode: Obsidian's own row, exactly as Obsidian renders it.
    const followingRow = result.coreTabWhileFollowing.rows.find((row) => row.name === 'Default location for new attachments');
    expect(followingRow?.hasDropdown).toBe(true);
    expect(followingRow?.description).not.toContain('Custom Attachment Location');
    expect(result.coreTabWhileFollowing.activeTabIdAfterButtonClick).toBeNull();
  }, 180_000);
});
