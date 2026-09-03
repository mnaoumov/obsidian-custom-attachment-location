import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { downloadReleasedPlugin } from '../scripts/helpers/download-released-plugin.ts';

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
 * This suite removes the assumption from both ends: the handler's RELEASED build is installed into the vault
 * and enabled, this plugin publishes the designation from its own settings, and the deletion is the real one.
 * A released artifact rather than a local build, deliberately — it is what a user installs, it pins to a
 * version this file can name, and it needs no checkout of the other repo.
 *
 * Desktop-only for the same reason as every other suite here: this is where the vault runs.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const HANDLER_PLUGIN_ID = 'advanced-rename-and-delete-handler';
const HANDLER_REPO = 'mnaoumov/obsidian-advanced-rename-and-delete-handler';

/**
 * The handler release under test.
 *
 * The whole-unit rescue is on the handler's `main` and lands in its **1.3.0**. Until that ships, the newest
 * released build is 1.2.0 — the version that still tears the unit apart — so pointing this suite at it
 * reproduces issue #70 rather than passing, which is how the harness proves it detects the defect at all.
 * Bump this to 1.3.0 once it is released.
 */
const HANDLER_VERSION = '1.2.0';

const WAIT_TIMEOUT_IN_MILLISECONDS = 30_000;
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
    const handlerFiles = await downloadReleasedPlugin({
      pluginId: HANDLER_PLUGIN_ID,
      repo: HANDLER_REPO,
      version: HANDLER_VERSION
    });

    const result = await evalInObsidian({
      async callback({
        app,
        backlinkCount,
        handlerMainJs,
        handlerManifestJson,
        handlerPluginId,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface UnitFolderSettings {
          attachmentFolderPath: string;
          attachmentUnitFolderPaths: string[];
          isAttachmentUnitFolder(path: string): boolean;
        }

        interface MigratableSettingsLike {
          readonly shouldHandleDeletions?: boolean;
          readonly shouldHandleRenames?: boolean;
          readonly shouldRescueSharedAttachments?: boolean;
        }

        interface MigrateSettingsParamsLike {
          readonly proposedSettings: MigratableSettingsLike;
          readonly sourcePluginId: string;
        }

        interface MigrateSettingsResultLike {
          readonly isApplied: boolean;
        }

        interface HandlerApiLike {
          migrateSettings(params: MigrateSettingsParamsLike): Promise<MigrateSettingsResultLike>;
        }

        interface PluginWithApiLike {
          readonly api: HandlerApiLike;
        }

        function isUnitFolderSettings(value: unknown): value is UnitFolderSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function';
        }

        /*
         * The plugin does not expose its settings publicly, so the live object the patch component reads is
         * located by walking the plugin's component tree — the same walk the designation suite uses.
         */
        function findSettings(): null | UnitFolderSettings {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [app.plugins.getPlugin(pluginId)];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            if (isUnitFolderSettings(record['settings'])) {
              return record['settings'];
            }
            let values: unknown[] = [];
            if (Array.isArray(current)) {
              values = current;
            } else if (current instanceof Map) {
              values = [...current.values()];
            } else {
              for (const [key, value] of Object.entries(record)) {
                if (!block.has(key)) {
                  values.push(value);
                }
              }
            }
            for (const value of values) {
              if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
                queue.push(value);
              }
            }
          }
          return null;
        }

        function hasApi(candidate: object): candidate is PluginWithApiLike {
          return 'api' in candidate;
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

        const foundSettings = findSettings();
        if (!foundSettings) {
          return {
            diagnostics: 'this plugin\'s live settings object was not found',
            doesDeletedFolderStillExist: false,
            isHandlerLoaded: false,
            isSettingsFound: false,
            survivingRelativePaths: []
          };
        }

        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: UnitFolderSettings = foundSettings;

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

        const handlerFolderPath = `${app.vault.configDir}/plugins/${handlerPluginId}`;
        const priorAttachmentFolderPath = settings.attachmentFolderPath;
        const priorUnitFolderPaths = settings.attachmentUnitFolderPaths;
        const priorAlwaysUpdateLinks = app.vault.getConfig('alwaysUpdateLinks');
        let isHandlerEnabled = false;

        try {
          await app.vault.adapter.mkdir(handlerFolderPath);
          await app.vault.adapter.write(`${handlerFolderPath}/manifest.json`, handlerManifestJson);
          await app.vault.adapter.write(`${handlerFolderPath}/main.js`, handlerMainJs);
          await app.plugins.loadManifests();

          /*
           * `enablePlugin`, not `enablePluginAndSave`: the shared vault must not remember the handler once
           * this file is done with it.
           */
          await app.plugins.enablePlugin(handlerPluginId);
          isHandlerEnabled = true;

          await waitUntil({
            message: 'the handler plugin never published its API',
            predicate: () => {
              const candidate = app.plugins.plugins[handlerPluginId];
              return candidate !== undefined && hasApi(candidate);
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const handlerPlugin = app.plugins.plugins[handlerPluginId];
          if (!handlerPlugin || !hasApi(handlerPlugin)) {
            return {
              diagnostics: 'the handler plugin loaded but exposes no API',
              doesDeletedFolderStillExist: false,
              isHandlerLoaded: false,
              isSettingsFound: true,
              survivingRelativePaths: []
            };
          }

          await applyHandlerSettings(handlerPlugin.api, {
            shouldHandleDeletions: true,
            shouldHandleRenames: true,
            shouldRescueSharedAttachments: true
          });

          /*
           * The rescue moves files through `app.fileManager.renameFile`, and Obsidian would otherwise raise
           * its own link-update confirmation, which a headless run cannot answer.
           */
          app.vault.setConfig('alwaysUpdateLinks', true);

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
            isHandlerLoaded: true,
            isSettingsFound: true,
            survivingRelativePaths: app.vault.getFiles()
              .map((file) => file.path)
              .filter((path) => path.startsWith(`${root}/`))
              .map((path) => path.slice(root.length + 1))
              .sort((left, right) => left.localeCompare(right))
          };
        } finally {
          settings.attachmentFolderPath = priorAttachmentFolderPath;
          settings.attachmentUnitFolderPaths = priorUnitFolderPaths;
          app.vault.setConfig('alwaysUpdateLinks', priorAlwaysUpdateLinks);

          if (isHandlerEnabled) {
            await app.plugins.disablePlugin(handlerPluginId);
          }

          /*
           * Through the adapter: a fixture teardown must not travel back through the very delete path the
           * handler patches, which would make the cleanup part of what is under test.
           */
          for (const path of [root, handlerFolderPath]) {
            if (await app.vault.adapter.exists(path)) {
              await app.vault.adapter.rmdir(path, true);
            }
          }

          // So the removed handler stops appearing in `app.plugins.manifests` for every later suite.
          await app.plugins.loadManifests();
        }
      },
      input: {
        backlinkCount: EXPECTED_BACKLINK_COUNT,
        handlerMainJs: handlerFiles.mainJs,
        handlerManifestJson: handlerFiles.manifestJson,
        handlerPluginId: HANDLER_PLUGIN_ID,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.diagnostics).toBe('');
    expect(result.isSettingsFound).toBe(true);
    expect(result.isHandlerLoaded).toBe(true);
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
