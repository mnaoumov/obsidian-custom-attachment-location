import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for the 14.0.0 move from the `${...}` token syntax to `{{...}}`.
 *
 * The unit tests prove the converter rewrites the strings. Only a real load proves the part a user meets: a
 * `data.json` written by 13.x, read by this build at startup, sends an attachment where the pre-migration settings
 * sent it, and is saved back in the new syntax. The plugin is reloaded over a hand-written legacy record, asked
 * through its published API where a note's attachments go, and then put back exactly as it was.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
// Under the transport's ~30s per-closure cap; each wait is one plugin reload in a small vault.
const WAIT_TIMEOUT_IN_MILLISECONDS = 8000;

interface MigrationResult {
  readonly apiFound: boolean;
  readonly expectedFolderPath: string;
  readonly folderPath: null | string;
  readonly savedAttachmentFolderPath: unknown;
  readonly savedGeneratedAttachmentFileName: unknown;
}

describe('Token syntax migration', () => {
  it('reads a 13.x data.json in the dollar-brace syntax and puts attachments where it did', async () => {
    const result = await evalInObsidian({
      async callback({ app, lib: { waitUntil }, pluginId, waitTimeoutInMilliseconds }): Promise<MigrationResult> {
        interface GetAttachmentFolderPathParams {
          readonly notePath: string;
        }

        interface ApiLike {
          getAttachmentFolderPath: (params: GetAttachmentFolderPathParams) => Promise<null | string>;
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

        function findApi(): ApiLike | null {
          const registryState = (window as Partial<ObsidianDevUtilsWrapper>).__obsidianDevUtils;
          const api = registryState?.pluginApiRegistry?.value?.records?.[pluginId]?.find((candidate) => !candidate.isRevoked)?.api;
          const record = api as null | Record<string, unknown> | undefined;
          return record && typeof record['getAttachmentFolderPath'] === 'function' ? api as ApiLike : null;
        }

        async function reloadPlugin(): Promise<ApiLike | null> {
          await app.plugins.disablePlugin(pluginId);
          await app.plugins.enablePlugin(pluginId);
          try {
            await waitUntil({
              message: 'the plugin API was not published again after the reload',
              predicate: () => findApi() !== null,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
          } catch {
            return null;
          }
          return findApi();
        }

        const adapter = app.vault.adapter;
        const dataPath = `${app.vault.configDir}/plugins/${pluginId}/data.json`;
        const originalData = await adapter.read(dataPath);

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const rootFolder = `tsm-${stamp}`;
        const noteBaseName = `Note ${stamp}`;
        const notePath = `${rootFolder}/${noteBaseName}.md`;
        // Built from pieces, so no string in this file is itself a legacy token.
        function legacyToken(name: string): string {
          return ['$', '{', name, '}'].join('');
        }

        await app.vault.createFolder(rootFolder);
        await app.vault.create(notePath, '');

        try {
          await adapter.write(
            dataPath,
            JSON.stringify({
              ...JSON.parse(originalData) as Record<string, unknown>,
              attachmentFolderPath: `./legacy/${legacyToken('noteFileName')}`,
              generatedAttachmentFileName: `img-${legacyToken('noteFileName')}`,
              shouldFollowObsidianAttachmentLocation: false,
              version: '13.0.0'
            })
          );

          const api = await reloadPlugin();
          if (!api) {
            return {
              apiFound: false,
              expectedFolderPath: '',
              folderPath: null,
              savedAttachmentFolderPath: null,
              savedGeneratedAttachmentFileName: null
            };
          }

          const folderPath = await api.getAttachmentFolderPath({ notePath });
          const saved = JSON.parse(await adapter.read(dataPath)) as Record<string, unknown>;
          return {
            apiFound: true,
            expectedFolderPath: `${rootFolder}/legacy/${noteBaseName}`,
            folderPath,
            savedAttachmentFolderPath: saved['attachmentFolderPath'],
            savedGeneratedAttachmentFileName: saved['generatedAttachmentFileName']
          };
        } finally {
          // Every later suite shares this instance, so the original record and a live plugin are restored.
          await adapter.write(dataPath, originalData);
          await reloadPlugin();
          const rootFolderFile = app.vault.getAbstractFileByPath(rootFolder);
          if (rootFolderFile) {
            await app.fileManager.trashFile(rootFolderFile);
          }
        }
      },
      input: {
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      }
    });

    expect(result.apiFound).toBe(true);
    expect(result.folderPath).toBe(result.expectedFolderPath);
    expect(result.savedAttachmentFolderPath).toBe('./legacy/{{noteFileName}}');
    expect(result.savedGeneratedAttachmentFileName).toBe('img-{{noteFileName}}');
  });
});
