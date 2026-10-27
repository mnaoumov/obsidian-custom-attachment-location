import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for the API member `getAvailablePathForAttachments`, which replaced the `extended` member
 * grafted onto the patched `Vault.getAvailablePathForAttachments` until 15.0.0.
 *
 * The questions are chosen so that a member answering with a constant, or with Obsidian's own location, would
 * fail: a note whose folder template is this plugin's, and the same question asked as a rename with an old note
 * path, so the context is mapped rather than dropped. The patched method itself is checked to carry no graft.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const ATTACHMENT_FOLDER_PATH = './_/{{noteFileName}}';

interface ProbeResult {
  readonly apiFound: boolean;
  readonly apiPaths: readonly string[];
  readonly graftMembers: readonly string[];
  readonly settingsFound: boolean;
}

describe('The plugin API resolves attachment paths with this plugin\'s template', () => {
  it('answers with the template for a plain and a rename question, and the vault method carries no graft', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        attachmentFolderPath,
        findPluginSettingsComponent: findSettingsComponent,
        pluginId
      }): Promise<ProbeResult> {
        interface ResolverParams {
          readonly attachmentFileBaseName: string;
          readonly attachmentFileExtension: string;
          readonly context: 'DeleteNote' | 'RenameNote' | 'Unknown';
          readonly notePathOrFile: null | string;
          readonly oldAttachmentPathOrFile: string;
          readonly oldNotePathOrFile?: string;
          readonly readAttachmentFileContent: null;
          readonly shouldSkipGeneratedAttachmentFileName?: boolean;
          readonly shouldSkipMissingAttachmentFolderCreation: boolean;
        }

        interface ApiLike {
          getAvailablePathForAttachments: (params: ResolverParams) => Promise<string>;
        }

        interface ApiRecord {
          readonly api: unknown;
          readonly isRevoked: boolean;
        }

        interface ObsidianLibWrapper {
          readonly __obsidianLib: ObsidianLibState;
        }

        interface ObsidianLibState {
          readonly pluginApiRegistry?: RegistryWrapper;
        }

        interface RegistryWrapper {
          readonly value?: RegistryValue;
        }

        interface RegistryValue {
          readonly records?: Record<string, ApiRecord[]>;
        }

        interface PathSettings {
          attachmentFolderPath: string;
        }

        const graftMembers = ['extended', 'checkIsAttachmentUnitFolder']
          .filter((member) => Reflect.get(app.vault.getAvailablePathForAttachments, member) !== undefined);

        function isApiLike(value: unknown): value is ApiLike {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['getAvailablePathForAttachments'] === 'function';
        }

        function isPathSettings(value: unknown): value is PathSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && typeof record['attachmentFolderPath'] === 'string'
            && typeof record['isAttachmentUnitFolder'] === 'function';
        }

        const record = (window as Partial<ObsidianLibWrapper>).__obsidianLib?.pluginApiRegistry?.value?.records?.[pluginId]
          ?.find((candidate) => !candidate.isRevoked);
        const api = record && isApiLike(record.api) ? record.api : null;
        if (!api) {
          return { apiFound: false, apiPaths: [], graftMembers, settingsFound: false };
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isPathSettings);
        if (!settingsComponent) {
          return { apiFound: true, apiPaths: [], graftMembers, settingsFound: false };
        }

        const priorFolderPath = settingsComponent.settings.attachmentFolderPath;
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const notePath = `api-path-${stamp}.md`;

        const questions: ResolverParams[] = [
          {
            attachmentFileBaseName: 'image',
            attachmentFileExtension: 'png',
            context: 'Unknown',
            notePathOrFile: notePath,
            oldAttachmentPathOrFile: 'image.png',
            readAttachmentFileContent: null,
            shouldSkipGeneratedAttachmentFileName: true,
            shouldSkipMissingAttachmentFolderCreation: true
          },
          {
            attachmentFileBaseName: 'image',
            attachmentFileExtension: 'png',
            context: 'RenameNote',
            notePathOrFile: notePath,
            oldAttachmentPathOrFile: 'image.png',
            oldNotePathOrFile: `api-path-old-${stamp}.md`,
            readAttachmentFileContent: null,
            shouldSkipGeneratedAttachmentFileName: true,
            shouldSkipMissingAttachmentFolderCreation: true
          }
        ];

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = attachmentFolderPath;
          });
          await app.vault.create(notePath, '');

          const apiPaths: string[] = [];
          for (const question of questions) {
            apiPaths.push(await api.getAvailablePathForAttachments(question));
          }

          return { apiFound: true, apiPaths, graftMembers, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorFolderPath;
          });
          const note = app.vault.getAbstractFileByPath(notePath);
          if (note) {
            await app.fileManager.trashFile(note);
          }
        }
      },
      input: {
        attachmentFolderPath: ATTACHMENT_FOLDER_PATH,
        findPluginSettingsComponent,
        pluginId: PLUGIN_ID
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.graftMembers).toEqual([]);
    expect(result.apiFound).toBe(true);
    expect(result.settingsFound).toBe(true);

    // This plugin's template, not Obsidian's location, for both contexts.
    expect(result.apiPaths).toHaveLength(2);
    for (const apiPath of result.apiPaths) {
      expect(apiPath).toMatch(/^_\/api-path-[\d-]+\/image\.png$/);
    }
  }, 120_000);
});
