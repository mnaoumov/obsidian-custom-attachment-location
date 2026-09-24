import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for `CustomAttachmentLocationApi.migrateSettings`, the receiving half of the collect-settings
 * handover from Consistent Attachments and Links.
 *
 * The API is read off the `obsidian-dev-utils` registry, which is what a consumer negotiates against, and the
 * dialog it opens is the real one, answered by pressing its real buttons. One run walks the whole contract:
 *
 *   - a proposal that changes nothing opens no dialog and counts as applied;
 *   - Cancel writes nothing and answers `isApplied: false`, so the consumer keeps its proposal;
 *   - OK writes the proposed value;
 *   - a second proposal carrying the original value puts it back through the same path, which is also how
 *     this suite leaves the shared vault as it found it.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const SOURCE_PLUGIN_ID = 'consistent-attachments-and-links';
const DIALOG_TITLE_PREFIX = 'Settings proposed by';
/*
 * Under the transport's ~30s per-closure cap, not at it. The closure waits for a dialog three times and for
 * nothing else, and each dialog opens in well under a second.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 5000;

interface ProbeResult {
  readonly apiFound: boolean;
  readonly apiVersion: string;
  readonly cancelResult: boolean | null;
  readonly didNoChangeOpenDialog: boolean;
  readonly modeAfterCancel: string;
  readonly modeAfterOk: string;
  readonly modeAfterRestore: string;
  readonly noChangeResult: boolean | null;
  readonly okResult: boolean | null;
  readonly proposedMode: string;
  readonly restoreResult: boolean | null;
  readonly rowCount: number;
  readonly settingsFound: boolean;
}

describe('migrateSettings', () => {
  it('asks through its own dialog, and writes only what the user approves', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        dialogTitlePrefix,
        lib: { waitUntil },
        pluginId,
        sourcePluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface MigrateSettingsParams {
          readonly proposedSettings: Record<string, unknown>;
          readonly sourcePluginId: string;
        }

        interface MigrateSettingsResult {
          readonly isApplied: boolean;
        }

        interface ApiLike {
          migrateSettings: (params: MigrateSettingsParams) => Promise<MigrateSettingsResult>;
        }

        interface ApiRecord {
          readonly api: unknown;
          readonly apiVersion: string;
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

        interface CollectSettings {
          collectAttachmentUsedByMultipleNotesMode: string;
          shouldCollectAttachmentsAutomatically: boolean;
        }

        const EMPTY: ProbeResult = {
          apiFound: false,
          apiVersion: '',
          cancelResult: null,
          didNoChangeOpenDialog: false,
          modeAfterCancel: '',
          modeAfterOk: '',
          modeAfterRestore: '',
          noChangeResult: null,
          okResult: null,
          proposedMode: '',
          restoreResult: null,
          rowCount: 0,
          settingsFound: false
        };

        function isApiLike(value: unknown): value is ApiLike {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null && typeof record['migrateSettings'] === 'function';
        }

        function isCollectSettings(value: unknown): value is CollectSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['collectAttachmentUsedByMultipleNotesMode'] === 'string'
            && typeof record['shouldCollectAttachmentsAutomatically'] === 'boolean';
        }

        const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;

        // The settings are not exposed publicly, so the live object is located by walking the plugin's
        // Component tree.
        function findSettings(): CollectSettings | null {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [pluginRecord];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            if (isCollectSettings(record['settings'])) {
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

        /*
         * Found by TITLE, never by a bare `.modal-container` lookup: a dialog of another plugin may be open
         * at the same time, and the first container in the DOM would then be the wrong one.
         */
        function findDialog(): HTMLElement | null {
          for (const containerEl of activeDocument.querySelectorAll<HTMLElement>('.modal-container')) {
            if (containerEl.querySelector('.modal-title')?.textContent.startsWith(dialogTitlePrefix)) {
              return containerEl;
            }
          }
          return null;
        }

        async function answerDialog(buttonText: string): Promise<number> {
          await waitUntil({
            message: `the ${dialogTitlePrefix} dialog did not open`,
            predicate: () => findDialog() !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          const dialogEl = findDialog();
          const rowCount = dialogEl?.querySelectorAll('.setting-item').length ?? 0;
          const buttonEl = [...dialogEl?.querySelectorAll('button') ?? []].find((candidate) => candidate.textContent === buttonText);
          if (!buttonEl) {
            throw new Error(`The ${dialogTitlePrefix} dialog has no ${buttonText} button`);
          }
          buttonEl.click();
          return rowCount;
        }

        const state = (window as Partial<ObsidianDevUtilsWrapper>).__obsidianDevUtils;
        const record = state?.pluginApiRegistry?.value?.records?.[pluginId]?.find((candidate) => !candidate.isRevoked);
        const api = record?.api;
        if (!record || !isApiLike(api)) {
          return EMPTY;
        }

        const settings = findSettings();
        if (!settings) {
          return { ...EMPTY, apiFound: true, apiVersion: record.apiVersion };
        }

        const priorMode = settings.collectAttachmentUsedByMultipleNotesMode;
        const proposedMode = priorMode === 'Copy' ? 'Move' : 'Copy';

        const noChange = await api.migrateSettings({
          proposedSettings: {
            collectAttachmentUsedByMultipleNotesMode: priorMode,
            shouldCollectAttachmentsAutomatically: settings.shouldCollectAttachmentsAutomatically
          },
          sourcePluginId
        });
        const didNoChangeOpenDialog = findDialog() !== null;

        const proposal = {
          proposedSettings: {
            collectAttachmentUsedByMultipleNotesMode: proposedMode,
            shouldCollectAttachmentsAutomatically: settings.shouldCollectAttachmentsAutomatically
          },
          sourcePluginId
        };

        const cancelPromise = api.migrateSettings(proposal);
        const rowCount = await answerDialog('Cancel');
        const cancelResult = await cancelPromise;
        const modeAfterCancel = settings.collectAttachmentUsedByMultipleNotesMode;

        const okPromise = api.migrateSettings(proposal);
        await answerDialog('OK');
        const okResult = await okPromise;
        const modeAfterOk = settings.collectAttachmentUsedByMultipleNotesMode;

        const restorePromise = api.migrateSettings({
          proposedSettings: { collectAttachmentUsedByMultipleNotesMode: priorMode },
          sourcePluginId
        });
        await answerDialog('OK');
        const restoreResult = await restorePromise;

        return {
          apiFound: true,
          apiVersion: record.apiVersion,
          cancelResult: cancelResult.isApplied,
          didNoChangeOpenDialog,
          modeAfterCancel,
          modeAfterOk,
          modeAfterRestore: settings.collectAttachmentUsedByMultipleNotesMode,
          noChangeResult: noChange.isApplied,
          okResult: okResult.isApplied,
          proposedMode,
          restoreResult: restoreResult.isApplied,
          rowCount,
          settingsFound: true
        };
      },
      input: {
        dialogTitlePrefix: DIALOG_TITLE_PREFIX,
        pluginId: PLUGIN_ID,
        sourcePluginId: SOURCE_PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.apiFound).toBe(true);
    expect(result.apiVersion).toBe('1.2.0');
    expect(result.settingsFound).toBe(true);

    expect(result.noChangeResult).toBe(true);
    expect(result.didNoChangeOpenDialog).toBe(false);

    // Only the setting that would change is shown: the automatic-collect value matched and was left out.
    expect(result.rowCount).toBe(1);
    expect(result.cancelResult).toBe(false);
    expect(result.modeAfterCancel).not.toBe(result.proposedMode);

    expect(result.okResult).toBe(true);
    expect(result.modeAfterOk).toBe(result.proposedMode);

    expect(result.restoreResult).toBe(true);
    expect(result.modeAfterRestore).toBe(result.modeAfterCancel);
  }, 60_000);
});
