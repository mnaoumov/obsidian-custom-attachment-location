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
 * The acceptance run for issue #71, with BOTH real plugins on one live vault.
 *
 * <https://github.com/mnaoumov/obsidian-custom-attachment-location/issues/71>: deleting a folder whose
 * attachment several surviving notes still reference used to stall silently — the folder holding the
 * attachment simply stayed. The request had two halves: consult the note-priority list before giving up, and,
 * when the top rank is TIED, name the tied notes and ask rather than stall.
 *
 * Both halves live in Advanced Rename and Delete Handler, which owns deletion interception since 12.0.0, and
 * both shipped in its 1.3.0. So there is no code in this repo to test — and that is exactly why this file
 * exists rather than being unnecessary.
 *
 * The handler's own suite stages the tie on Obsidian's BUILT-IN attachment location, with this plugin never
 * installed. The reporter runs this plugin. So the tie had never once executed against the patched
 * `Vault.getAvailablePathForAttachments` this plugin installs, which is the seam a reported defect hides in:
 * the dialog resolves to a note, and where that note's attachments actually live is this plugin's answer, not
 * Obsidian's.
 *
 * This suite removes that assumption. The handler's RELEASED build is in the vault and enabled, this plugin's
 * own `./assets` policy is what decides the destination, the tie is genuine — both survivors share the best
 * rank in a non-empty priority list — and the deletion is the real one. Sibling of
 * `attachment-unit-folder-rescue-cross-plugin.desktop.integration.test.ts`, which does the same for issue #70.
 *
 * Desktop-only for the same reason as every other suite here: this is where the vault runs.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const HANDLER_PLUGIN_ID = ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID;

/*
 * The handler release under test is the seeded one — 1.3.0, the first to carry the ambiguity dialog, pinned in
 * the seed rather than following `latest`, for the reason stated on `DownloadReleasedPluginParams.version`.
 *
 * The pin is also what makes this suite falsifiable, and that was RUN rather than reasoned about. Pointed at
 * 1.2.0 — the last release before the dialog — it reproduces issue #71 instead of passing: `askWhoAdopts`
 * does not exist there, so the tie resolves to "leave it in place" and no dialog is ever raised. The run
 * dies on this file's own wait, naming the defect: `the ambiguity dialog never opened, so the tie was
 * settled without asking`. Since the seed carries the pin for every suite, repeating that means pointing the
 * seed at 1.2.0 for one run — which still satisfies the dependency, because 1.2.0 already publishes contract
 * 1.1.0, so this plugin still loads and still patches the attachment path.
 */
const HANDLER_VERSION = ADVANCED_RENAME_AND_DELETE_HANDLER_VERSION;

/*
 * One entry that every note in the fixture matches, so the list is consulted, matches, and still names no
 * winner. That is a genuine `Tie` — distinct from the `EmptyList` a vault with no list produces, and it is
 * the case the reporter hit and the one half of the request that was actually missing.
 */
const TIED_PRIORITY_ENTRY = '.md';

/*
 * Quoted from the handler's `getNoPriorityWinnerReasonText`. Restated here on purpose: this is an acceptance
 * test against a PINNED release of another plugin, so what the user is told is part of what is accepted, and
 * importing it would make the assertion follow whatever that plugin says next.
 */
const EXPECTED_REASON_TEXT = 'Several of these notes tie for the best rank in the Note priorities setting, so it names no single owner.';

const EXPECTED_MODAL_TITLE = 'Attachment used by several notes';

/*
 * The handler's own settings-migration dialog, which this file opens twice on its way in and out. It has to
 * be told apart from the dialog under test by title: both are open at once whenever an assertion inside the
 * ambiguity dialog fails, and a bare `.modal-container` lookup then takes whichever is first in the DOM — so
 * the teardown's throw replaces the failure that caused it, and the run reports the wrong defect.
 */
const MIGRATION_MODAL_TITLE_PREFIX = 'Settings proposed by ';

/*
 * The handler labels each button `Move to ${basename(notePath)}`, and a basename keeps its extension — so
 * the label carries `.md`. Asserted in full below rather than matched loosely: the labels ARE the box this
 * request asked for, and the sibling request to drop the extension is tracked separately on that plugin.
 */
const CHOSEN_BUTTON_TEXT = 'Move to Alpha.md';

/*
 * Under the transport's ~30s default per-closure cap, not at it. The project raises its CDP command timeout
 * well past that, but only as a backstop: a closure that spends it dies as a bare transport timeout naming the
 * harness, never the wait that overran. The one closure below charges this ceiling SEVEN times — the handler's
 * API, the settings dialog on the way in and on the way back, the backlink index, the ambiguity dialog opening,
 * its list of notes, and the deletion — plus a one-second settle, and the whole callback is a single
 * evaluation, so it is the sum that has to fit. Every one of those waits is for an event that fires within moments on a quiet machine.
 *
 * Consumed only inside the closure. The Node-side budget is `TEST_TIMEOUT_IN_MILLISECONDS`, which the cap does
 * not govern.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 3000;
const TEST_TIMEOUT_IN_MILLISECONDS = 180_000;
const EXPECTED_BACKLINK_COUNT = 3;
const TIED_NOTE_COUNT = 2;

interface ProbeResult {
  /**
   * The label of every button the dialog offered, in the order it offered them.
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
   * Whether the handler plugin loaded and published its API.
   */
  readonly isHandlerLoaded: boolean;

  /**
   * Whether this plugin's settings component was found.
   */
  readonly isSettingsFound: boolean;

  /**
   * The rendered text of each note the dialog listed as still referencing the attachment.
   */
  readonly listedNoteTexts: readonly string[];

  /**
   * The dialog's title, so the box the request asked for is identified rather than merely counted.
   */
  readonly modalTitle: string;

  /**
   * The sentence the dialog gave for why the priority list named no owner.
   */
  readonly reasonText: string;

  /**
   * Every file left under the fixture root once the deletion settled, relative to that root and sorted.
   *
   * The whole shape rather than one path probe: the destination is the point of this file, and an attachment
   * left where it was looks identical to one moved to the wrong note until the surviving tree is read out.
   */
  readonly survivingRelativePaths: readonly string[];
}

describe('Deleting a folder whose shared attachment ties at the top of the note-priority list (issue #71)', () => {
  it('names both tied notes and moves the attachment into the chosen one\'s attachment folder', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        backlinkCount,
        chosenButtonText,
        expectedModalTitle,
        findPluginSettingsComponent: findSettingsComponent,
        handlerPluginId,
        lib: { waitUntil },
        migrationModalTitlePrefix,
        pluginId,
        tiedNoteCount,
        tiedPriorityEntry,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface AttachmentFolderSettings {
          attachmentFolderPath: string;
          isAttachmentUnitFolder: (path: string) => boolean;
        }

        interface MigratableSettingsLike {
          readonly notePriorities?: readonly string[];
          readonly shouldHandleDeletions?: boolean;
          readonly shouldHandleRenames?: boolean;
          readonly shouldRescueSharedAttachments?: boolean;
        }

        interface HandedOverSettingsLike {
          readonly notePriorities: readonly string[];
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

        function isAttachmentFolderSettings(value: unknown): value is AttachmentFolderSettings {
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
         * Finds an open modal by how its title starts, so one dialog is told from another.
         *
         * Two different dialogs are raised during this run — the handler's settings-migration one and the
         * ambiguity one under test — and a bare `.modal-container` lookup cannot tell them apart. It picks
         * whichever is first in the DOM, which is how a failed assertion inside the ambiguity dialog used to
         * come back as "the settings dialog has no OK button": the teardown found the wrong box and its throw
         * replaced the real one.
         *
         * @param titlePrefix - What the wanted dialog's title starts with.
         * @returns The modal's container element, or `null` when no open modal's title starts with it.
         */
        function findModalElByTitlePrefix(titlePrefix: string): HTMLElement | null {
          for (const containerEl of document.querySelectorAll<HTMLElement>('.modal-container')) {
            if (containerEl.querySelector('.modal-title')?.textContent.startsWith(titlePrefix) ?? false) {
              return containerEl;
            }
          }

          return null;
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

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isAttachmentFolderSettings);
        if (!settingsComponent) {
          return {
            buttonTexts: [],
            diagnostics: 'this plugin\'s settings component was not found',
            doesDeletedFolderStillExist: false,
            handlerVersion: '',
            isHandlerLoaded: false,
            isSettingsFound: false,
            listedNoteTexts: [],
            modalTitle: '',
            reasonText: '',
            survivingRelativePaths: []
          };
        }

        /*
         * One Obsidian instance is shared with every other integration file, so every path is stamped and
         * every value written here is snapshotted and put back.
         */
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const root = `x-plugin-tie-${stamp}`;
        const deletedFolderPath = `${root}/deleted`;
        const attachmentPath = `${deletedFolderPath}/assets/image.png`;
        const ownerNotePath = `${deletedFolderPath}/Owner.md`;
        const alphaNotePath = `${root}/alpha/Alpha.md`;
        const bravoNotePath = `${root}/bravo/Bravo.md`;

        const priorAttachmentFolderPath = settingsComponent.settings.attachmentFolderPath;
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
              buttonTexts: [],
              diagnostics: 'the handler plugin loaded but exposes no API',
              doesDeletedFolderStillExist: false,
              handlerVersion: '',
              isHandlerLoaded: false,
              isSettingsFound: true,
              listedNoteTexts: [],
              modalTitle: '',
              reasonText: '',
              survivingRelativePaths: []
            };
          }

          // The handler outlives this file, so what it held is handed back in the `finally` below.
          handlerApi = foundHandlerApi;
          const currentHandlerSettings = handlerApi.getSettings();
          priorHandlerSettings = {
            notePriorities: currentHandlerSettings.notePriorities,
            shouldHandleDeletions: currentHandlerSettings.shouldHandleDeletions,
            shouldHandleRenames: currentHandlerSettings.shouldHandleRenames,
            shouldRescueSharedAttachments: currentHandlerSettings.shouldRescueSharedAttachments
          };

          /*
           * `rescueAttachmentUsedByMultipleNotesMode` is deliberately not proposed: the handler does not offer
           * it for migration, and its default is already the `Prompt` this suite needs.
           */
          await applyHandlerSettings(handlerApi, {
            notePriorities: [tiedPriorityEntry],
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
           * A subfolder of each note's OWN folder, so the three notes resolve to three different attachment
           * folders. Without that the destination would be the same wherever the dialog's answer pointed, and
           * this file would assert nothing about whose policy computed it.
           */
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = './assets';
          });

          await app.vault.createFolder(`${deletedFolderPath}/assets`);
          await app.vault.createFolder(`${root}/alpha`);
          await app.vault.createFolder(`${root}/bravo`);
          const attachmentFile = await app.vault.createBinary(attachmentPath, new ArrayBuffer(8));
          await app.vault.create(ownerNotePath, `![[${attachmentPath}]]\n`);
          await app.vault.create(alphaNotePath, `![[${attachmentPath}]]\n`);
          await app.vault.create(bravoNotePath, `![[${attachmentPath}]]\n`);

          await waitUntil({
            message: 'all three references to the attachment are indexed',
            predicate: () => app.metadataCache.getBacklinksForFile(attachmentFile).keys().length === backlinkCount,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const deletedFolder = app.vault.getFolderByPath(deletedFolderPath);
          if (!deletedFolder) {
            throw new Error(`${deletedFolderPath} was not created`);
          }

          /*
           * Not awaited yet: the deletion blocks on the very dialog this file is here to read, so awaiting it
           * first would deadlock the run against an answer nobody has given.
           */
          const deletionPromise = app.fileManager.trashFile(deletedFolder);

          await waitUntil({
            message: 'the ambiguity dialog never opened, so the tie was settled without asking',
            predicate: () => findModalElByTitlePrefix(expectedModalTitle) !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const modalEl = findModalElByTitlePrefix(expectedModalTitle);
          if (!modalEl) {
            throw new Error('the ambiguity dialog closed before it could be read');
          }

          /*
           * The links are rendered asynchronously while the buttons are built synchronously, so the list is
           * the one part of the dialog that has to be waited for.
           */
          await waitUntil({
            message: 'the dialog never listed the notes still referencing the attachment',
            predicate: () => modalEl.querySelectorAll(':scope .rescue-ambiguity-notes li').length === tiedNoteCount,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const buttons = [...modalEl.querySelectorAll<HTMLButtonElement>(':scope .rescue-ambiguity-buttons button')];
          const probe = {
            buttonTexts: buttons.map((button) => button.textContent),
            listedNoteTexts: [...modalEl.querySelectorAll(':scope .rescue-ambiguity-notes li')].map((itemEl) => itemEl.textContent),
            modalTitle: modalEl.querySelector('.modal-title')?.textContent ?? '',
            reasonText: modalEl.querySelector('.rescue-ambiguity-reason')?.textContent ?? ''
          };

          const chosenButton = buttons.find((button) => button.textContent === chosenButtonText);
          if (!chosenButton) {
            throw new Error(`the dialog offered no button for the chosen note: ${probe.buttonTexts.join(', ')}`);
          }

          chosenButton.click();
          await deletionPromise;

          await waitUntil({
            message: 'the deleted folder never disappeared, so the deletion did not finish',
            predicate: () => app.vault.getFolderByPath(deletedFolderPath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          // A settled read: the owning note's own deletion is reported after the walk and re-runs the links.
          await sleep(1000);

          return {
            ...probe,
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
        chosenButtonText: CHOSEN_BUTTON_TEXT,
        expectedModalTitle: EXPECTED_MODAL_TITLE,
        findPluginSettingsComponent,
        handlerPluginId: HANDLER_PLUGIN_ID,
        migrationModalTitlePrefix: MIGRATION_MODAL_TITLE_PREFIX,
        pluginId: PLUGIN_ID,
        tiedNoteCount: TIED_NOTE_COUNT,
        tiedPriorityEntry: TIED_PRIORITY_ENTRY,
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

    // Part 2 of the request: the box, naming the tied notes rather than stalling in silence.
    expect(result.modalTitle).toBe(EXPECTED_MODAL_TITLE);
    expect(result.reasonText).toBe(EXPECTED_REASON_TEXT);
    expect(result.listedNoteTexts).toHaveLength(TIED_NOTE_COUNT);
    expect(result.listedNoteTexts.join('\n')).toContain('Alpha');
    expect(result.listedNoteTexts.join('\n')).toContain('Bravo');
    expect(result.buttonTexts).toStrictEqual([
      CHOSEN_BUTTON_TEXT,
      'Move to Bravo.md',
      'Leave it here'
    ]);

    /*
     * The seam this file exists for: the attachment sits under `alpha/assets`, which is THIS plugin's
     * `./assets` policy applied to the note the user picked. Obsidian's built-in location — the one the
     * handler's own suite runs against — would have put it somewhere else entirely.
     */
    expect(result.survivingRelativePaths).toStrictEqual([
      'alpha/Alpha.md',
      'alpha/assets/image.png',
      'bravo/Bravo.md'
    ]);
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});
