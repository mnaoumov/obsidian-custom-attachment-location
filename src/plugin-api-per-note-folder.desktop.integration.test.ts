import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for the published per-note read (`CustomAttachmentLocationApi.getAttachmentFolderPath`).
 *
 * The defect it replaces is not a crash, it is a wrong answer that looks right. This plugin patches
 * `Vault.getConfig('attachmentFolderPath')`, and that patch answers with the OPEN note's folder — the value is
 * computed once in `handleFileOpen` and held in a single field. A consumer auditing a vault note by note gets
 * the active note's folder for every one of them, silently.
 *
 * So the shape staged here is exactly that: two notes whose configured folders differ, with only the FIRST of
 * them open. A single run reads three things — the patched `getConfig`, the API asked about the open note, and
 * the API asked about the one that is not open. The patch must answer with the open note's folder for the
 * vault, and the API must answer with each note's own. Without the second reading, a read that simply returned
 * the same field would pass.
 *
 * The same staging then drives the acting member, `collectAttachments`: the open note's embedded image is
 * collected through the registry handle, and is read at the proper path the moment the promise settles — which
 * is what a consumer sequencing on the collect relies on, and what a promise that settled on queueing would fail.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
// eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
const ATTACHMENT_FOLDER_PATH = './_/${noteFileName}';
/*
 * Under the transport's ~30s per-closure cap, not at it. The closure spends this ceiling twice — once for the
 * file-open field to be filled, once for the staged embed to be indexed — and every step is a write into a
 * small temporary vault.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 6000;

interface ProbeResult {
  readonly apiFolderForClosedNote: null | string;
  readonly apiFolderForOpenNote: null | string;
  readonly apiFound: boolean;
  readonly apiVersion: string;
  readonly collectedImagePath: null | string;
  readonly contractMethodNames: readonly string[];
  readonly getConfigFolder: string;
  readonly properAttachmentPath: null | string;
  readonly settingsFound: boolean;
}

describe('The published API answers per note, which the getConfig patch cannot', () => {
  it('answers each note own attachment folder while getConfig answers the open note for both', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        attachmentFolderPath,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface GetAttachmentFolderPathParams {
          readonly attachmentFileName?: string;
          readonly notePath: string;
        }

        interface GetProperAttachmentPathParams {
          readonly attachmentPathOrFile: string;
          readonly notePath: string;
        }

        interface CollectAttachmentsParams {
          readonly pathsOrFiles: readonly string[];
        }

        interface ApiLike {
          collectAttachments(params: CollectAttachmentsParams): Promise<void>;
          getAttachmentFolderPath(params: GetAttachmentFolderPathParams): Promise<null | string>;
          getProperAttachmentPath(params: GetProperAttachmentPathParams): Promise<null | string>;
        }

        interface ApiRecord {
          readonly api: unknown;
          readonly apiVersion: string;
          readonly contract: Record<string, unknown>;
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

        interface FolderSettings {
          attachmentFolderPath: string;
          shouldRenameCollectedAttachments: boolean;
        }

        const EMPTY: ProbeResult = {
          apiFolderForClosedNote: null,
          apiFolderForOpenNote: null,
          apiFound: false,
          apiVersion: '',
          collectedImagePath: null,
          contractMethodNames: [],
          getConfigFolder: '',
          properAttachmentPath: null,
          settingsFound: false
        };

        function isApiLike(value: unknown): value is ApiLike {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['collectAttachments'] === 'function'
            && typeof record['getAttachmentFolderPath'] === 'function'
            && typeof record['getProperAttachmentPath'] === 'function';
        }

        function isFolderSettings(value: unknown): value is FolderSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['shouldRenameCollectedAttachments'] === 'boolean';
        }

        const pluginRecord = app.plugins.getPlugin(pluginId) as null | Record<string, unknown>;

        // The settings are not exposed publicly, so the live object the resolver reads is located by walking
        // The plugin's component tree.
        function findSettings(): FolderSettings | null {
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
            if (isFolderSettings(record['settings'])) {
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
         * The registry, read where it lives rather than through `watchPluginApi`: the closure runs in the
         * renderer realm with no bundle of its own, and the point of this reading is that a STRANGER can find
         * the record — which is what a consumer's watch resolves to anyway.
         */
        /*
         * The bag `obsidian-dev-utils` keeps its registry in lives on the main renderer's global, which is
         * the window this closure and every plugin bundle share.
         */
        const registryState = (window as Partial<ObsidianDevUtilsWrapper>).__obsidianDevUtils;
        const record = registryState?.pluginApiRegistry?.value?.records?.[pluginId]
          ?.find((candidate) => !candidate.isRevoked);

        if (!record || !isApiLike(record.api)) {
          return EMPTY;
        }

        const api = record.api;
        const settings = findSettings();

        if (!settings) {
          return { ...EMPTY, apiFound: true, apiVersion: record.apiVersion, contractMethodNames: Object.keys(record.contract).sort() };
        }

        const priorFolderPath = settings.attachmentFolderPath;
        const wasRenamingCollectedAttachments = settings.shouldRenameCollectedAttachments;

        async function trashIfExists(path: string): Promise<void> {
          const existing = app.vault.getAbstractFileByPath(path);
          if (!existing) {
            return;
          }
          try {
            await app.fileManager.trashFile(existing);
          } catch {
            // Already gone, which is the outcome this wanted anyway.
          }
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const openNoteBaseName = `api-open-${stamp}`;
        const closedNoteBaseName = `api-closed-${stamp}`;
        const imageFileName = `api-img-${stamp}.png`;

        try {
          settings.attachmentFolderPath = attachmentFolderPath;
          // The staged name must survive, or the asserted proper path could not name the file it was staged as.
          settings.shouldRenameCollectedAttachments = false;

          await app.vault.createBinary(imageFileName, new ArrayBuffer(4));
          const openNote = await app.vault.create(`${openNoteBaseName}.md`, `![[${imageFileName}]]\n`);
          await app.vault.create(`${closedNoteBaseName}.md`, '');

          await app.workspace.getLeaf(false).openFile(openNote);

          /*
           * The patched `getConfig` answers with `null` until `handleFileOpen` has filled its field, so a read
           * taken too early would report Obsidian's own setting and quietly prove nothing.
           */
          await waitUntil({
            message: 'the file-open handler never filled the patched getConfig value',
            predicate: () => app.vault.getConfig('attachmentFolderPath') === `_/${openNoteBaseName}`,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          await waitUntil({
            message: 'the staged embed was not indexed',
            predicate: () => {
              const imageFile = app.vault.getFileByPath(imageFileName);
              return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length > 0;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const apiFolderForClosedNote = await api.getAttachmentFolderPath({ notePath: `${closedNoteBaseName}.md` });
          const apiFolderForOpenNote = await api.getAttachmentFolderPath({ notePath: `${openNoteBaseName}.md` });
          const getConfigFolder = String(app.vault.getConfig('attachmentFolderPath'));
          const properAttachmentPath = await api.getProperAttachmentPath({
            attachmentPathOrFile: imageFileName,
            notePath: `${openNoteBaseName}.md`
          });

          // Read the instant the promise settles, with no wait in between: that is the promise under test.
          await api.collectAttachments({ pathsOrFiles: [`${openNoteBaseName}.md`] });
          const collectedImagePath = properAttachmentPath !== null && app.vault.getFileByPath(properAttachmentPath) !== null
            ? properAttachmentPath
            : null;

          return {
            apiFolderForClosedNote,
            apiFolderForOpenNote,
            apiFound: true,
            apiVersion: record.apiVersion,
            collectedImagePath,
            contractMethodNames: Object.keys(record.contract).sort(),
            getConfigFolder,
            properAttachmentPath,
            settingsFound: true
          };
        } finally {
          settings.attachmentFolderPath = priorFolderPath;
          settings.shouldRenameCollectedAttachments = wasRenamingCollectedAttachments;
          for (const path of [`${openNoteBaseName}.md`, `${closedNoteBaseName}.md`, imageFileName, `_/${openNoteBaseName}`]) {
            await trashIfExists(path);
          }
        }
      },
      input: {
        attachmentFolderPath: ATTACHMENT_FOLDER_PATH,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.apiFound).toBe(true);
    expect(result.settingsFound).toBe(true);

    // The record a consumer negotiates against.
    // `1.1.0` added `migrateSettings` and `1.2.0` `collectAttachments`; the two reads are unchanged since `1.0.0`, so a
    // `'^1'` consumer still matches.
    expect(result.apiVersion).toBe('1.2.0');
    expect(result.contractMethodNames).toEqual(['collectAttachments', 'getAttachmentFolderPath', 'getProperAttachmentPath', 'migrateSettings']);

    // The defect: one value for the whole vault, and it is the OPEN note's.
    expect(result.getConfigFolder).toMatch(/^_\/api-open-/);

    // The fix: each note's own, including the one that was never opened.
    expect(result.apiFolderForOpenNote).toMatch(/^_\/api-open-/);
    expect(result.apiFolderForClosedNote).toMatch(/^_\/api-closed-/);
    expect(result.apiFolderForClosedNote).not.toBe(result.getConfigFolder);

    // The acting half: where the embedded attachment belongs, folder and file name both.
    expect(result.properAttachmentPath).toMatch(/^_\/api-open-.*\/api-img-.*\.png$/);

    // And the acting member: collected through the registry handle, and already there when the promise settles.
    expect(result.collectedImagePath).toBe(result.properAttachmentPath);
  }, 120_000);
});
