import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * An enable after layout-ready: a manual enable, an update, or a lazy loader that enables the plugin after
 * layout-ready on every start.
 *
 * On that path the layout-ready handler runs one tick after load, while `data.json` is still being read. It used
 * to register the custom tokens from whatever `customTokensStr` held at that moment, which was the DEFAULT, and
 * nothing registered them again. A folder template that uses one of the user's own tokens then resolved without it.
 * Disabling and re-enabling the plugin in a running vault is exactly that path, so it needs no lazy loader.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
// Under the transport's ~30s per-closure cap; each wait is one plugin reload in a small vault.
const WAIT_TIMEOUT_IN_MILLISECONDS = 8000;

interface LateEnableResult {
  readonly apiFound: boolean;
  readonly expectedFolderPath: string;
  readonly folderPath: null | string;
  readonly savedAttachmentFolderPath: unknown;
}

describe('Custom tokens on an enable after layout-ready', () => {
  it('registers the stored custom tokens, not the default ones', async () => {
    const result = await evalInObsidian({
      async callback({ app, lib: { waitUntil }, pluginId, waitTimeoutInMilliseconds }): Promise<LateEnableResult> {
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
        const rootFolder = `late-enable-${stamp}`;
        const notePath = `${rootFolder}/Note ${stamp}.md`;
        const tokenValue = `late-token-${stamp}`;
        const attachmentFolderPath = './{{lateEnableToken}}';

        await app.vault.createFolder(rootFolder);
        await app.vault.create(notePath, '');

        try {
          await adapter.write(
            dataPath,
            JSON.stringify({
              ...JSON.parse(originalData) as Record<string, unknown>,
              attachmentFolderPath,
              // eslint-disable-next-line unicorn/name-replacements -- `customTokensStr` is a persisted `data.json` settings key.
              customTokensStr: `registerCustomToken('lateEnableToken', () => '${tokenValue}');`,
              shouldFollowObsidianAttachmentLocation: false
            })
          );

          const api = await reloadPlugin();
          if (!api) {
            return {
              apiFound: false,
              expectedFolderPath: '',
              folderPath: null,
              savedAttachmentFolderPath: null
            };
          }

          // The API is published before the layout-ready handler finishes, so give that handler time to settle.
          const expectedFolderPath = `${rootFolder}/${tokenValue}`;
          let folderPath: null | string = null;
          try {
            await waitUntil({
              message: 'the attachment folder never resolved the custom token',
              async predicate() {
                folderPath = await api.getAttachmentFolderPath({ notePath });
                return folderPath === expectedFolderPath;
              },
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
          } catch {
            // The assertion below reports the last value read.
          }
          const saved = JSON.parse(await adapter.read(dataPath)) as Record<string, unknown>;
          return {
            apiFound: true,
            expectedFolderPath,
            folderPath,
            savedAttachmentFolderPath: saved['attachmentFolderPath']
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
    expect(result.savedAttachmentFolderPath).toBe('./{{lateEnableToken}}');
  });
});
