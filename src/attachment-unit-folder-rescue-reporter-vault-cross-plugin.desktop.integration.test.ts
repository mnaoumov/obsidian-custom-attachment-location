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
 * The follow-up to issue #70, on the layout of the reporter's second sample vault rather than on the one
 * `attachment-unit-folder-rescue-cross-plugin.desktop.integration.test.ts` models.
 *
 * <https://github.com/mnaoumov/obsidian-custom-attachment-location/issues/70>: after both halves of the fix
 * shipped, the reporter came back with a vault that differs from the acceptance suite's fixture in every
 * dimension the rescue branches on:
 *
 * - the unit folder is designated by a REGEX (`/(^|\/)@\/[^/]+$/`), not by a literal path;
 * - the note-relative attachment folder is `./@`, so the unit sits at `B/@/Environment`;
 * - the unit folder holds a NOTE (`Untitled.md`, empty) beside the image, so the deletion walk counts it among
 *   the deleted notes;
 * - three notes reference the image, so two survive — which leaves the handler's priority list tied and
 *   raises its ambiguity dialog — and all three notes are named `Note.md`.
 *
 * The acceptance suite is green on none of those, so this file stages all of them at once against the same
 * released handler, with its deletion handling ON. The reporter's own vault shipped with it OFF — the
 * handler's `shouldHandleDeletions` is `false` in the zip, which alone accounts for the video: nothing is
 * intercepted, and the whole folder goes. This file is what answers whether turning it on is enough.
 *
 * Desktop-only for the same reason as every other suite here: this is where the vault runs.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const HANDLER_PLUGIN_ID = ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID;
const HANDLER_VERSION = ADVANCED_RENAME_AND_DELETE_HANDLER_VERSION;

// Verbatim from the reporter's `data.json`.
const REPORTER_ATTACHMENT_FOLDER_PATH = './@';
const REPORTER_UNIT_FOLDER_PATTERN = String.raw`/(^|\/)@\/[^/]+$/`;

const EXPECTED_MODAL_TITLE = 'Attachment used by several notes';
const MIGRATION_MODAL_TITLE_PREFIX = 'Settings proposed by ';

/*
 * Under the transport's ~30s default per-closure cap, not at it. The project raises its CDP command timeout
 * well past that, but only as a backstop: a closure that spends it dies as a bare transport timeout naming the
 * harness, never the wait that overran. The one closure below charges this ceiling SIX times — the settings
 * dialog on the way in and on the way back, and four waits of its own — plus a one-second settle, and the whole
 * callback is a single evaluation, so it is the sum that has to fit. Every one of those waits is for an event
 * that fires within moments on a quiet machine. Sized as the sibling rescue suite's is.
 *
 * Consumed only inside the closure. The Node-side budget is `TEST_TIMEOUT_IN_MILLISECONDS`, which the cap does
 * not govern.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 3500;
const TEST_TIMEOUT_IN_MILLISECONDS = 180_000;
const EXPECTED_BACKLINK_COUNT = 3;
const EXPECTED_BUTTON_COUNT = 3;

interface ProbeResult {
  /**
   * The label of every button the ambiguity dialog offered, in order; empty when it never opened.
   */
  readonly buttonTexts: readonly string[];

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
   * Whether this plugin designated the reporter's unit folder at all, read before the deletion.
   */
  readonly isUnitFolderDesignated: boolean;

  /**
   * Every file left under the fixture root once the deletion settled, relative to that root and sorted.
   */
  readonly survivingRelativePaths: readonly string[];
}

describe('Deleting a folder on the layout of the reporter\'s second sample vault (issue #70)', () => {
  it('moves the whole unit, the note inside it included, into the adopting note\'s area', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        backlinkCount,
        expectedModalTitle,
        findPluginSettingsComponent: findSettingsComponent,
        handlerPluginId,
        lib: { waitUntil },
        migrationModalTitlePrefix,
        pluginId,
        reporterAttachmentFolderPath,
        reporterUnitFolderPattern,
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

        interface PluginWithApiLike {
          readonly api: HandlerApiLike;
        }

        function hasApi(candidate: object): candidate is PluginWithApiLike {
          return 'api' in candidate;
        }

        function isUnitFolderSettings(value: unknown): value is UnitFolderSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function';
        }

        // By title, never a bare `.modal-container` lookup — see this repo's `AGENTS.md`.
        function findModalElByTitlePrefix(titlePrefix: string): HTMLElement | null {
          for (const containerEl of document.querySelectorAll<HTMLElement>('.modal-container')) {
            if (containerEl.querySelector('.modal-title')?.textContent.startsWith(titlePrefix) ?? false) {
              return containerEl;
            }
          }

          return null;
        }

        async function applyHandlerSettings(api: HandlerApiLike, proposedSettings: MigratableSettingsLike): Promise<void> {
          const migrationPromise = api.migrateSettings({ proposedSettings, sourcePluginId: pluginId });
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
            predicate: () => isSettled || findModalElByTitlePrefix(migrationModalTitlePrefix) !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const modalEl = findModalElByTitlePrefix(migrationModalTitlePrefix);
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
          throw new Error('this plugin\'s live settings object was not found');
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const root = `x-plugin-reporter-vault-${stamp}`;
        const deletedFolderPath = `${root}/B`;
        const unitFolderPath = `${deletedFolderPath}/@/Environment`;
        const imagePath = `${unitFolderPath}/Nature.png`;
        const notePathInsideUnit = `${unitFolderPath}/Untitled.md`;
        const adoptingNotePath = `${root}/A/Note.md`;

        const priorAttachmentFolderPath = settingsComponent.settings.attachmentFolderPath;
        const priorUnitFolderPaths = settingsComponent.settings.attachmentUnitFolderPaths;
        const priorAlwaysUpdateLinks = app.vault.getConfig('alwaysUpdateLinks');
        let handlerApi: HandlerApiLike | null = null;
        let priorHandlerSettings: MigratableSettingsLike | null = null;

        try {
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
            throw new Error('the handler plugin loaded but exposes no API');
          }

          handlerApi = handlerPlugin.api;
          const currentHandlerSettings = handlerApi.getSettings();
          priorHandlerSettings = {
            shouldHandleDeletions: currentHandlerSettings.shouldHandleDeletions,
            shouldHandleRenames: currentHandlerSettings.shouldHandleRenames,
            shouldRescueSharedAttachments: currentHandlerSettings.shouldRescueSharedAttachments
          };

          /*
           * The reporter's handler settings, with ONE change: deletions on. Their zip has it off, and with it
           * off nothing is intercepted at all — which is not the question this file asks.
           */
          await applyHandlerSettings(handlerApi, {
            shouldHandleDeletions: true,
            shouldHandleRenames: false,
            shouldRescueSharedAttachments: true
          });

          app.vault.setConfig('alwaysUpdateLinks', true);
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = reporterAttachmentFolderPath;
            settings.attachmentUnitFolderPaths = [reporterUnitFolderPattern];
          });

          await app.vault.createFolder(unitFolderPath);
          await app.vault.createFolder(`${root}/A`);
          await app.vault.createFolder(`${root}/C`);
          const image = await app.vault.createBinary(imagePath, new ArrayBuffer(8));
          await app.vault.create(notePathInsideUnit, '');
          for (const folderName of ['A', 'B', 'C']) {
            await app.vault.create(`${root}/${folderName}/Note.md`, `![[${imagePath}]]`);
          }

          await waitUntil({
            message: 'all three references to the image are indexed',
            predicate: () => app.metadataCache.getBacklinksForFile(image).keys().length === backlinkCount,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const isUnitFolderDesignated = settingsComponent.settings.isAttachmentUnitFolder(unitFolderPath);

          const deletedFolder = app.vault.getFolderByPath(deletedFolderPath);
          if (!deletedFolder) {
            throw new Error(`${deletedFolderPath} was not created`);
          }

          // Not awaited yet: two survivors tie, so the deletion blocks on the handler's ambiguity dialog.
          const deletionPromise = app.fileManager.trashFile(deletedFolder);

          let buttonTexts: string[] = [];
          await waitUntil({
            message: 'neither the ambiguity dialog opened nor the deletion finished',
            predicate: () => findModalElByTitlePrefix(expectedModalTitle) !== null || app.vault.getFolderByPath(deletedFolderPath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const modalEl = findModalElByTitlePrefix(expectedModalTitle);
          if (modalEl) {
            const buttons = [...modalEl.querySelectorAll<HTMLButtonElement>(':scope .rescue-ambiguity-buttons button')];
            buttonTexts = buttons.map((button) => button.textContent);

            /*
             * Every note in the reporter's vault is `Note.md`, so the labels cannot tell A from C; the tooltip
             * carries the full path, and that is what picks the adopter.
             */
            const chosenButton = buttons.find((button) => button.getAttribute('aria-label')?.includes(adoptingNotePath) ?? false);
            if (!chosenButton) {
              throw new Error(`the dialog offered no button for ${adoptingNotePath}: ${buttonTexts.join(', ')}`);
            }

            chosenButton.click();
          }

          await deletionPromise;

          await waitUntil({
            message: 'the deleted folder never disappeared, so the deletion did not finish',
            predicate: () => app.vault.getFolderByPath(deletedFolderPath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          await sleep(1000);

          return {
            buttonTexts,
            diagnostics: '',
            doesDeletedFolderStillExist: app.vault.getFolderByPath(deletedFolderPath) !== null,
            handlerVersion: app.plugins.manifests[handlerPluginId]?.version ?? '',
            isUnitFolderDesignated,
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
        expectedModalTitle: EXPECTED_MODAL_TITLE,
        findPluginSettingsComponent,
        handlerPluginId: HANDLER_PLUGIN_ID,
        migrationModalTitlePrefix: MIGRATION_MODAL_TITLE_PREFIX,
        pluginId: PLUGIN_ID,
        reporterAttachmentFolderPath: REPORTER_ATTACHMENT_FOLDER_PATH,
        reporterUnitFolderPattern: REPORTER_UNIT_FOLDER_PATTERN,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.diagnostics).toBe('');
    expect(result.handlerVersion).toBe(HANDLER_VERSION);
    expect(result.isUnitFolderDesignated).toBe(true);
    expect(result.doesDeletedFolderStillExist).toBe(false);
    /*
     * The two survivors tie, so the dialog is asked: one button per survivor plus `Leave it here`. Counted rather
     * than matched, because the pinned release labels both survivors `Move to Note.md`; the handler has since
     * disambiguated same-named notes, and this file should not pin the label it is about to lose.
     */
    expect(result.buttonTexts).toHaveLength(EXPECTED_BUTTON_COUNT);
    expect(result.survivingRelativePaths).toStrictEqual([
      'A/@/Environment/Nature.png',
      'A/@/Environment/Untitled.md',
      'A/Note.md',
      'C/Note.md'
    ]);
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});
