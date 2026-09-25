import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import {
  ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
  ADVANCED_RENAME_AND_DELETE_HANDLER_VERSION
} from '../scripts/helpers/advanced-rename-and-delete-handler-seed.ts';
import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * The acceptance run for issue #70, with BOTH real plugins on one live vault.
 *
 * <https://github.com/mnaoumov/obsidian-custom-attachment-location/issues/70>: two folders, each holding a
 * note, both referencing one attachment that lives in an attachment unit folder. Deleting one folder rescued
 * the lone linked file and left the rest of the unit behind, so the surviving note inherited a torn tree.
 *
 * The fix spans two plugins: this one publishes the unit-folder designation on the patched
 * `Vault.getAvailablePathForAttachments`, and Advanced Rename and Delete Handler — which owns delete
 * interception since 12.0.0 — reads it back and moves the whole folder.
 *
 * Neither repo could prove that on its own, and both said so. The handler's own suite stages the designation
 * with a stub "without installing the plugin that publishes it"; this repo's
 * `attachment-unit-folder-designation.desktop.integration.test.ts` drives the publish side with no consumer
 * at all. So each side has only ever run against an assumption about the other, which is precisely the seam
 * the reporter stood on.
 *
 * This suite removes the assumption from both ends: the handler's RELEASED build is in the vault and enabled,
 * this plugin publishes the designation from its own settings, and the deletion is the real one. A released
 * artifact rather than a local build, deliberately — it is what a user installs, it pins to a version this file
 * can name, and it needs no checkout of the other repo.
 *
 * The handler is not installed here any more: this plugin declares it as a dependency and cannot load without
 * it, so the global setup seeds it into every vault (`scripts/helpers/advanced-rename-and-delete-handler-seed.ts`).
 * This suite turns on the handler settings it needs and hands them back afterwards, because the handler
 * outlives the file.
 *
 * Desktop-only for the same reason as every other suite here: this is where the vault runs.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const HANDLER_PLUGIN_ID = ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID;

/*
 * The handler release under test is the seeded one — 1.3.0, the first to carry the whole-unit rescue, pinned in
 * the seed rather than following `latest`, for the reason stated on `DownloadReleasedPluginParams.version`.
 *
 * The pin is also what makes this suite falsifiable. Pointed at 1.2.0 — the last release before the rescue,
 * which still tears the unit apart — it reproduces issue #70 instead of passing, leaving `a/A.md` and
 * `a/assets/image.png`: the linked file pulled OUT of its unit folder and dropped beside it, and the
 * unreferenced sibling destroyed with the deleted folder. That run is how the harness was shown to detect the
 * defect at all rather than to pass vacuously. Since the seed carries the pin for every suite, repeating it
 * means pointing the seed at 1.2.0 for one run — which still satisfies the dependency, because 1.2.0 already
 * publishes contract 1.1.0.
 */
const HANDLER_VERSION = ADVANCED_RENAME_AND_DELETE_HANDLER_VERSION;

/*
 * Under the transport's ~30s default per-closure cap, not at it. The project raises its CDP command timeout
 * well past that, but only as a backstop: a closure that spends it dies as a bare transport timeout naming the
 * harness, never the wait that overran. The one closure below charges this ceiling FIVE times — the handler's
 * API, the settings dialog on the way in, the backlink index, the deletion, and the settings dialog on the way
 * back — plus a one-second settle, and the whole callback is a single evaluation, so it is the sum that has to
 * fit. Every one of those waits is for an event that fires within moments on a quiet machine; the ceiling is
 * headroom for a loaded one, not a budget for slow work.
 *
 * Consumed only inside the closure. The Node-side budget is `TEST_TIMEOUT_IN_MILLISECONDS`, which the cap does
 * not govern.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 3500;
const TEST_TIMEOUT_IN_MILLISECONDS = 180_000;
const EXPECTED_BACKLINK_COUNT = 2;

interface ProbeResult {
  /**
   * Diagnostics for a run that never reached the assertions.
   */
  readonly diagnostics: string;

  /**
   * Whether the folder the user deleted is gone, so the deletion itself ran.
   */
  readonly doesDeletedFolderStillExist: boolean;

  /**
   * The version of the handler actually in the vault, so the pin is checked rather than assumed.
   */
  readonly handlerVersion: string;

  /**
   * Whether the handler plugin loaded and published its API.
   */
  readonly isHandlerLoaded: boolean;

  /**
   * Whether this plugin's live settings object was found.
   */
  readonly isSettingsFound: boolean;

  /**
   * Every file left under the fixture root once the deletion settled, relative to that root and sorted.
   *
   * The whole shape rather than two path probes: a torn unit is only legible next to where its pieces
   * actually went, and a rescue that lands the lone file beside the unit folder looks identical to one that
   * lands nothing until the surviving tree is read out.
   */
  readonly survivingRelativePaths: readonly string[];
}

describe('Deleting a folder whose shared attachment sits in an attachment unit folder (issue #70)', () => {
  it('moves the whole unit into the surviving note\'s area, with the real handler installed', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        backlinkCount,
        findPluginSettingsComponent: findSettingsComponent,
        handlerPluginId,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface UnitFolderSettings {
          attachmentFolderPath: string;
          attachmentUnitFolderPaths: string[];
          isAttachmentUnitFolder: (path: string) => boolean;
        }

        interface MigratableSettingsLike {
          readonly shouldHandleDeletions?: boolean;
          readonly shouldHandleRenames?: boolean;
          readonly shouldRescueSharedAttachments?: boolean;
        }

        interface HandedOverSettingsLike {
          readonly shouldHandleDeletions: boolean;
          readonly shouldHandleRenames: boolean;
          readonly shouldRescueSharedAttachments: boolean;
        }

        interface MigrateSettingsParamsLike {
          readonly proposedSettings: MigratableSettingsLike;
          readonly sourcePluginId: string;
        }

        interface MigrateSettingsResultLike {
          readonly isApplied: boolean;
        }

        interface HandlerApiLike {
          getSettings: () => HandedOverSettingsLike;
          migrateSettings: (params: MigrateSettingsParamsLike) => Promise<MigrateSettingsResultLike>;
        }

        interface ApiRecord {
          readonly api: unknown;
          readonly isRevoked: boolean;
        }

        interface ObsidianDevUtilsWrapper {
          readonly __obsidianDevUtils: ObsidianDevUtilsState;
        }

        interface ObsidianDevUtilsState {
          readonly pluginApiRegistry?: RegistryWrapper;
        }

        interface RegistryWrapper {
          readonly value?: RegistryValue;
        }

        interface RegistryValue {
          readonly records?: Record<string, ApiRecord[]>;
        }

        function isUnitFolderSettings(value: unknown): value is UnitFolderSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function';
        }

        /*
         * The handler publishes its API through the plugin API registry alone since 2.0.0, which removed the
         * `api` getter on its plugin instance.
         */
        function findHandlerApi(): HandlerApiLike | null {
          const registryState = (window as Partial<ObsidianDevUtilsWrapper>).__obsidianDevUtils;
          const api = registryState?.pluginApiRegistry?.value?.records?.[handlerPluginId]?.find((candidate) => !candidate.isRevoked)?.api;
          const record = api as null | Record<string, unknown> | undefined;
          return record && typeof record['migrateSettings'] === 'function' ? api as HandlerApiLike : null;
        }

        /**
         * Writes the handler's settings through its own migration API, approving the dialog it raises.
         *
         * Its settings are its own, so they are proposed rather than written: that is the only supported way
         * in, and it is the same path this plugin's migration component takes.
         *
         * @param api - The handler's published API.
         * @param proposedSettings - The values to propose.
         */
        async function applyHandlerSettings(api: HandlerApiLike, proposedSettings: MigratableSettingsLike): Promise<void> {
          const migrationPromise = api.migrateSettings({
            proposedSettings,
            sourcePluginId: pluginId
          });
          let isSettled = false;
          const settlementPromise = migrationPromise
            .then(() => {
              isSettled = true;
            })
            .catch(() => {
              isSettled = true;
            });

          await waitUntil({
            message: 'the handler\'s settings dialog opens, or the proposal turns out to change nothing',
            predicate: () => isSettled || document.querySelector('.modal-container') !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const modalEl = document.querySelector('.modal-container');
          if (modalEl) {
            const okButton = [...modalEl.querySelectorAll('button')].find((button) => button.textContent === 'OK');
            if (!okButton) {
              throw new Error('the handler\'s settings dialog has no OK button');
            }

            okButton.click();
          }

          await settlementPromise;
          const migrateSettingsResult = await migrationPromise;
          if (!migrateSettingsResult.isApplied) {
            throw new Error('the handler did not apply the proposed settings');
          }
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isUnitFolderSettings);
        if (!settingsComponent) {
          return {
            diagnostics: 'this plugin\'s live settings object was not found',
            doesDeletedFolderStillExist: false,
            handlerVersion: '',
            isHandlerLoaded: false,
            isSettingsFound: false,
            survivingRelativePaths: []
          };
        }

        /*
         * One Obsidian instance is shared with every other integration file, so every path is stamped and
         * every value written here is snapshotted and put back.
         */
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const root = `x-plugin-unit-rescue-${stamp}`;
        const deletedFolderPath = `${root}/deleted`;
        const unitFolderPath = `${deletedFolderPath}/assets/drawing_files`;
        const linkedFilePath = `${unitFolderPath}/image.png`;
        const siblingPath = `${unitFolderPath}/style.css`;
        const ownerNotePath = `${deletedFolderPath}/Owner.md`;
        const survivorNotePath = `${root}/a/A.md`;

        const priorAttachmentFolderPath = settingsComponent.settings.attachmentFolderPath;
        const priorUnitFolderPaths = settingsComponent.settings.attachmentUnitFolderPaths;
        const priorAlwaysUpdateLinks = app.vault.getConfig('alwaysUpdateLinks');
        let handlerApi: HandlerApiLike | null = null;
        let priorHandlerSettings: MigratableSettingsLike | null = null;

        try {
          // Seeded and enabled by the global setup — which is also what let this plugin load at all.
          await waitUntil({
            message: 'the handler plugin never published its API',
            predicate: () => {
              return findHandlerApi() !== null;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const foundHandlerApi = findHandlerApi();
          if (!foundHandlerApi) {
            return {
              diagnostics: 'the handler plugin loaded but exposes no API',
              doesDeletedFolderStillExist: false,
              handlerVersion: '',
              isHandlerLoaded: false,
              isSettingsFound: true,
              survivingRelativePaths: []
            };
          }

          // The handler outlives this file, so what it held is handed back in the `finally` below.
          handlerApi = foundHandlerApi;
          const currentHandlerSettings = handlerApi.getSettings();
          priorHandlerSettings = {
            shouldHandleDeletions: currentHandlerSettings.shouldHandleDeletions,
            shouldHandleRenames: currentHandlerSettings.shouldHandleRenames,
            shouldRescueSharedAttachments: currentHandlerSettings.shouldRescueSharedAttachments
          };

          await applyHandlerSettings(handlerApi, {
            shouldHandleDeletions: true,
            shouldHandleRenames: true,
            shouldRescueSharedAttachments: true
          });

          /*
           * The rescue moves files through `app.fileManager.renameFile`, and Obsidian would otherwise raise
           * its own link-update confirmation, which a headless run cannot answer.
           */
          app.vault.setConfig('alwaysUpdateLinks', true);

          await settingsComponent.editAndSave((settings) => {
            /*
             * A subfolder of each note's OWN folder, so the deleted note and the survivor resolve to different
             * attachment folders and the rescue actually has somewhere to move the unit to.
             */
            settings.attachmentFolderPath = './assets';

            /*
             * The designation is published for real, off this plugin's own setting, rather than stubbed onto
             * the patched function. That is the whole point of this file.
             */
            settings.attachmentUnitFolderPaths = [unitFolderPath];
          });

          await app.vault.createFolder(unitFolderPath);
          await app.vault.createFolder(`${root}/a`);
          const linkedFile = await app.vault.createBinary(linkedFilePath, new ArrayBuffer(8));
          // Referenced by nothing: it survives only because the unit it belongs to travels whole.
          await app.vault.create(siblingPath, 'body { color: red; }\n');
          await app.vault.create(ownerNotePath, `![[${linkedFilePath}]]\n`);
          await app.vault.create(survivorNotePath, `![[${linkedFilePath}]]\n`);

          await waitUntil({
            message: 'both references to the linked file are indexed',
            predicate: () => app.metadataCache.getBacklinksForFile(linkedFile).keys().length === backlinkCount,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const deletedFolder = app.vault.getFolderByPath(deletedFolderPath);
          if (!deletedFolder) {
            throw new Error(`${deletedFolderPath} was not created`);
          }

          await app.fileManager.trashFile(deletedFolder);

          /*
           * The deletion walks the tree and the rescue runs inside that walk, so the settled state is the
           * one where the folder the user named is gone.
           */
          await waitUntil({
            message: 'the deleted folder never disappeared, so the deletion did not finish',
            predicate: () => app.vault.getFolderByPath(deletedFolderPath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          // A settled read: the owning note's own deletion is reported after the walk and re-runs the links.
          await sleep(1000);

          return {
            diagnostics: '',
            doesDeletedFolderStillExist: app.vault.getFolderByPath(deletedFolderPath) !== null,
            handlerVersion: app.plugins.manifests[handlerPluginId]?.version ?? '',
            isHandlerLoaded: true,
            isSettingsFound: true,
            survivingRelativePaths: app.vault.getFiles()
              .map((file) => file.path)
              .filter((path) => path.startsWith(`${root}/`))
              .map((path) => path.slice(root.length + 1))
              .sort((left, right) => left.localeCompare(right))
          };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorAttachmentFolderPath;
            settings.attachmentUnitFolderPaths = priorUnitFolderPaths;
          });
          app.vault.setConfig('alwaysUpdateLinks', priorAlwaysUpdateLinks);

          /*
           * Through the adapter: a fixture teardown must not travel back through the very delete path the
           * handler patches, which would make the cleanup part of what is under test. And before the handler's
           * settings go back, so the deletions are still off-limits to it by the time they are removed.
           */
          if (await app.vault.adapter.exists(root)) {
            await app.vault.adapter.rmdir(root, true);
          }

          if (handlerApi && priorHandlerSettings) {
            await applyHandlerSettings(handlerApi, priorHandlerSettings);
          }
        }
      },
      input: {
        backlinkCount: EXPECTED_BACKLINK_COUNT,
        findPluginSettingsComponent,
        handlerPluginId: HANDLER_PLUGIN_ID,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.diagnostics).toBe('');
    expect(result.isSettingsFound).toBe(true);
    expect(result.isHandlerLoaded).toBe(true);
    // The pin is only a statement about something if the handler in the vault is the pinned one.
    expect(result.handlerVersion).toBe(HANDLER_VERSION);
    expect(result.doesDeletedFolderStillExist).toBe(false);

    /*
     * The surviving note, and the whole unit folder beside it: the linked file still INSIDE the unit rather
     * than pulled out next to it, and the sibling nothing referenced — the piece the lone-file rescue leaves
     * behind to be deleted, which is issue #70 itself.
     */
    expect(result.survivingRelativePaths).toStrictEqual([
      'a/A.md',
      'a/assets/drawing_files/image.png',
      'a/assets/drawing_files/style.css'
    ]);
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});
