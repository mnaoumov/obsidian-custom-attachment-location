import type { CustomArrayDict } from '@obsidian-typings/obsidian-public-latest';
import type {
  App,
  PluginManifest,
  Reference,
  TAbstractFile,
  TFile
} from 'obsidian';
import type { Mock } from 'vitest';

import {
  noop,
  noopAsync
} from 'obsidian-dev-utils/function';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import {
  getAbstractFileOrNull,
  getFileOrNull
} from 'obsidian-dev-utils/obsidian/file-system';
import { getBacklinksForFileSafe } from 'obsidian-dev-utils/obsidian/metadata-cache';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { AttachmentCollector } from './attachment-collector.ts';
import type { AttachmentPathManager } from './attachment-path-manager.ts';
import type { SettingsMigrationRow } from './collect-settings-migration.ts';
import type { HandedOverSettingsComponent } from './handed-over-settings-component.ts';
import type { ShowCollectSettingsMigrationModalParams } from './modals/collect-settings-migration-modal.ts';
import type { PluginSettingsComponent } from './plugin-settings-component.ts';

import { showCollectSettingsMigrationModal } from './modals/collect-settings-migration-modal.ts';
import { PluginApiImpl } from './plugin-api-impl.ts';
import { PLUGIN_API_CONTRACT } from './plugin-api.ts';
import {
  CollectAttachmentUsedByMultipleNotesMode,
  PluginSettings
} from './plugin-settings.ts';
import { ActionContext } from './token-evaluator-context.ts';

vi.mock('./modals/collect-settings-migration-modal.ts', () => ({
  showCollectSettingsMigrationModal: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/file-system', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/file-system')>(),
  getAbstractFileOrNull: vi.fn(),
  getFileOrNull: vi.fn()
}));

vi.mock('obsidian-dev-utils/obsidian/metadata-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('obsidian-dev-utils/obsidian/metadata-cache')>(),
  getBacklinksForFileSafe: vi.fn()
}));

const mockGetBacklinksForFileSafe = vi.mocked(getBacklinksForFileSafe);
const mockGetAbstractFileOrNull = vi.mocked(getAbstractFileOrNull);
const mockGetFileOrNull = vi.mocked(getFileOrNull);

const ATTACHMENT_FILE = createFile('Attachments/image.png');
const NOTE_PATH = 'Notes/Alpha.md';

function createBacklinks(referencesByNotePath: Record<string, Reference[]>): CustomArrayDict<Reference> {
  return strictProxy<CustomArrayDict<Reference>>({
    get: (key: string) => referencesByNotePath[key] ?? null
  });
}

function createFile(path: string): TFile {
  return strictProxy<TFile>({
    extension: path.split('.').at(-1) ?? '',
    name: path.split('/').at(-1) ?? '',
    path
  });
}

describe('PluginApiImpl', () => {
  let collectAttachmentsInAbstractFilesAndWait: Mock<AttachmentCollector['collectAttachmentsInAbstractFilesAndWait']>;
  let getAttachmentFolderFullPathForPath: Mock<AttachmentPathManager['getAttachmentFolderFullPathForPath']>;
  let getProperAttachmentPath: Mock<AttachmentPathManager['getProperAttachmentPath']>;
  let getSequenceNumberMap: Mock<AttachmentPathManager['getSequenceNumberMap']>;
  let ignoredPaths: Set<string>;
  let pluginApi: PluginApiImpl;

  beforeEach(() => {
    vi.clearAllMocks();

    ignoredPaths = new Set<string>();
    collectAttachmentsInAbstractFilesAndWait = vi.fn().mockResolvedValue(undefined);
    getAttachmentFolderFullPathForPath = vi.fn().mockResolvedValue('Attachments/Alpha');
    getProperAttachmentPath = vi.fn().mockResolvedValue('Attachments/Alpha/image.png');
    getSequenceNumberMap = vi.fn().mockResolvedValue(new Map([[ATTACHMENT_FILE.path, 3]]));

    pluginApi = new PluginApiImpl({
      app: strictProxy<App>({}),
      attachmentCollector: strictProxy<AttachmentCollector>({
        collectAttachmentsInAbstractFilesAndWait
      }),
      attachmentPathManager: strictProxy<AttachmentPathManager>({
        getAttachmentFolderFullPathForPath,
        getProperAttachmentPath,
        getSequenceNumberMap
      }),
      handedOverSettingsComponent: strictProxy<HandedOverSettingsComponent>({
        isPathIgnored: (path: string) => ignoredPaths.has(path)
      }),
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({})
    });

    mockGetFileOrNull.mockReturnValue(ATTACHMENT_FILE);
    mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks({ [NOTE_PATH]: [strictProxy<Reference>({})] }));
  });

  it('should declare every method the contract names', () => {
    for (const methodName of Object.keys(PLUGIN_API_CONTRACT)) {
      expect(pluginApi).toHaveProperty(methodName, expect.any(Function));
    }
  });

  describe('collectAttachments', () => {
    const NOTE_FILE = createFile(NOTE_PATH);

    beforeEach(() => {
      mockGetAbstractFileOrNull.mockImplementation(({ pathOrFile }) => {
        if (typeof pathOrFile !== 'string') {
          return pathOrFile;
        }
        return pathOrFile === NOTE_PATH ? NOTE_FILE : null;
      });
    });

    it('should resolve paths and hand the files to the collector', async () => {
      await pluginApi.collectAttachments({ pathsOrFiles: [NOTE_PATH] });

      expect(collectAttachmentsInAbstractFilesAndWait).toHaveBeenCalledWith([NOTE_FILE]);
    });

    it('should pass a file or folder the caller already holds straight through', async () => {
      const folder = strictProxy<TAbstractFile>({ path: 'Notes' });

      await pluginApi.collectAttachments({ pathsOrFiles: [folder] });

      expect(collectAttachmentsInAbstractFilesAndWait).toHaveBeenCalledWith([folder]);
    });

    it('should skip an entry that names nothing in the vault', async () => {
      await pluginApi.collectAttachments({ pathsOrFiles: ['Missing.md', NOTE_PATH] });

      expect(collectAttachmentsInAbstractFilesAndWait).toHaveBeenCalledWith([NOTE_FILE]);
    });

    // An empty list is not a no-op to the collector: it confirms several-or-none with the user.
    it('should not reach the collector when nothing named exists', async () => {
      await pluginApi.collectAttachments({ pathsOrFiles: ['Missing.md'] });

      expect(collectAttachmentsInAbstractFilesAndWait).not.toHaveBeenCalled();
    });

    it('should settle only once the collect has finished', async () => {
      let finishCollect: () => void = noop;
      collectAttachmentsInAbstractFilesAndWait.mockReturnValue(
        new Promise<void>((resolve) => {
          finishCollect = resolve;
        })
      );
      let isSettled = false;

      const collectPromise = pluginApi.collectAttachments({ pathsOrFiles: [NOTE_PATH] }).then(() => {
        isSettled = true;
      });
      await noopAsync();
      expect(isSettled).toBe(false);

      finishCollect();
      await collectPromise;
      expect(isSettled).toBe(true);
    });
  });

  describe('getAttachmentFolderPath', () => {
    it('should answer for the note it was asked about', async () => {
      await expect(pluginApi.getAttachmentFolderPath({ notePath: NOTE_PATH })).resolves.toBe('Attachments/Alpha');

      expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledWith(expect.objectContaining({ notePath: NOTE_PATH }));
    });

    it('should read in a context that never asks the user anything', async () => {
      await pluginApi.getAttachmentFolderPath({ notePath: NOTE_PATH });

      expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledWith(expect.objectContaining({ actionContext: ActionContext.ReadApi }));
    });

    it('should stand the placeholder name in when the caller named no attachment', async () => {
      await pluginApi.getAttachmentFolderPath({ notePath: NOTE_PATH });

      expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledWith(expect.objectContaining({ attachmentFileName: DUMMY_PATH }));
    });

    it('should pass the attachment name on when the caller supplied one', async () => {
      await pluginApi.getAttachmentFolderPath({ attachmentFileName: 'image.png', notePath: NOTE_PATH });

      expect(getAttachmentFolderFullPathForPath).toHaveBeenCalledWith(expect.objectContaining({ attachmentFileName: 'image.png' }));
    });

    it('should answer with null for a note the plugin leaves alone', async () => {
      ignoredPaths.add(NOTE_PATH);

      await expect(pluginApi.getAttachmentFolderPath({ notePath: NOTE_PATH })).resolves.toBeNull();
      expect(getAttachmentFolderFullPathForPath).not.toHaveBeenCalled();
    });
  });

  describe('getProperAttachmentPath', () => {
    it('should answer with the path the attachment belongs at', async () => {
      await expect(pluginApi.getProperAttachmentPath({ attachmentPathOrFile: ATTACHMENT_FILE.path, notePath: NOTE_PATH }))
        .resolves.toBe('Attachments/Alpha/image.png');
    });

    it('should resolve the sequence number from the note own numbering', async () => {
      await pluginApi.getProperAttachmentPath({ attachmentPathOrFile: ATTACHMENT_FILE.path, notePath: NOTE_PATH });

      expect(getSequenceNumberMap).toHaveBeenCalledWith(NOTE_PATH);
      expect(getProperAttachmentPath).toHaveBeenCalledWith(expect.objectContaining({
        actionContext: ActionContext.ReadApi,
        sequenceNumber: 3
      }));
    });

    it('should fall back to sequence number 0 when the note numbers no such attachment', async () => {
      getSequenceNumberMap.mockResolvedValue(new Map());

      await pluginApi.getProperAttachmentPath({ attachmentPathOrFile: ATTACHMENT_FILE.path, notePath: NOTE_PATH });

      expect(getProperAttachmentPath).toHaveBeenCalledWith(expect.objectContaining({
        sequenceNumber: 0
      }));
    });

    it('should answer with null for a path no file answers to', async () => {
      mockGetFileOrNull.mockReturnValue(null);

      await expect(pluginApi.getProperAttachmentPath({ attachmentPathOrFile: 'Never/Written.png', notePath: NOTE_PATH })).resolves.toBeNull();
      expect(getProperAttachmentPath).not.toHaveBeenCalled();
    });

    it('should answer with null when the note does not reference the attachment', async () => {
      mockGetBacklinksForFileSafe.mockResolvedValue(createBacklinks({ 'Notes/Beta.md': [strictProxy<Reference>({})] }));

      await expect(pluginApi.getProperAttachmentPath({ attachmentPathOrFile: ATTACHMENT_FILE.path, notePath: NOTE_PATH })).resolves.toBeNull();
      expect(getProperAttachmentPath).not.toHaveBeenCalled();
    });

    it('should answer with null for an attachment the plugin leaves alone', async () => {
      ignoredPaths.add(ATTACHMENT_FILE.path);

      await expect(pluginApi.getProperAttachmentPath({ attachmentPathOrFile: ATTACHMENT_FILE.path, notePath: NOTE_PATH })).resolves.toBeNull();
      expect(getProperAttachmentPath).not.toHaveBeenCalled();
    });

    it('should answer with null for a note the plugin leaves alone', async () => {
      ignoredPaths.add(NOTE_PATH);

      await expect(pluginApi.getProperAttachmentPath({ attachmentPathOrFile: ATTACHMENT_FILE.path, notePath: NOTE_PATH })).resolves.toBeNull();
      expect(getProperAttachmentPath).not.toHaveBeenCalled();
    });
  });

  describe('migrateSettings', () => {
    const SOURCE_PLUGIN_ID = 'consistent-attachments-and-links';

    let editAndSaveCallCount: number;
    let settings: PluginSettings;

    function createMigratingPluginApi(manifests: Readonly<Record<string, PluginManifest>> = {}): PluginApiImpl {
      return new PluginApiImpl({
        /*
         * A plain object rather than a `strictProxy`: the lookup asks for an id that is deliberately absent in
         * the not-installed case, and a strict proxy throws on a missing key instead of answering `undefined`
         * the way the real record does.
         */
        app: castTo<App>({ plugins: { manifests } }),
        attachmentCollector: strictProxy<AttachmentCollector>({}),
        attachmentPathManager: strictProxy<AttachmentPathManager>({}),
        handedOverSettingsComponent: strictProxy<HandedOverSettingsComponent>({}),
        pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
          async editAndSave(settingsEditor: (settingsToEdit: PluginSettings) => Promise<void> | void): Promise<void> {
            editAndSaveCallCount++;
            await settingsEditor(settings);
          },
          settings
        })
      });
    }

    beforeEach(() => {
      editAndSaveCallCount = 0;
      settings = new PluginSettings();
    });

    it('should write what the user approved', async () => {
      vi.mocked(showCollectSettingsMigrationModal).mockImplementation(
        (params: ShowCollectSettingsMigrationModalParams): Promise<null | SettingsMigrationRow[]> => Promise.resolve([...params.rows])
      );

      const result = await createMigratingPluginApi().migrateSettings({
        proposedSettings: {
          collectAttachmentUsedByMultipleNotesMode: 'Move',
          shouldCollectAttachmentsAutomatically: true
        },
        sourcePluginId: SOURCE_PLUGIN_ID
      });

      expect(result.isApplied).toBe(true);
      expect(settings.collectAttachmentUsedByMultipleNotesMode).toBe(CollectAttachmentUsedByMultipleNotesMode.Move);
      expect(settings.shouldCollectAttachmentsAutomatically).toBe(true);
      expect(editAndSaveCallCount).toBe(1);
    });

    it('should write nothing when the user cancels', async () => {
      vi.mocked(showCollectSettingsMigrationModal).mockResolvedValue(null);

      const result = await createMigratingPluginApi().migrateSettings({
        proposedSettings: { shouldCollectAttachmentsAutomatically: true },
        sourcePluginId: SOURCE_PLUGIN_ID
      });

      expect(result.isApplied).toBe(false);
      expect(settings.shouldCollectAttachmentsAutomatically).toBe(false);
      expect(editAndSaveCallCount).toBe(0);
    });

    it('should ask nothing when the proposal changes nothing, and still count as migrated', async () => {
      const result = await createMigratingPluginApi().migrateSettings({
        proposedSettings: {
          collectAttachmentUsedByMultipleNotesMode: 'Skip',
          excludePathsFromAttachmentCollecting: []
        },
        sourcePluginId: SOURCE_PLUGIN_ID
      });

      expect(result.isApplied).toBe(true);
      expect(showCollectSettingsMigrationModal).not.toHaveBeenCalled();
      expect(editAndSaveCallCount).toBe(0);
    });

    it('should name the proposing plugin by its display name when it is installed', async () => {
      vi.mocked(showCollectSettingsMigrationModal).mockResolvedValue(null);

      await createMigratingPluginApi({
        [SOURCE_PLUGIN_ID]: castTo<PluginManifest>({ name: 'Consistent Attachments and Links' })
      }).migrateSettings({
        proposedSettings: { shouldCollectAttachmentsAutomatically: true },
        sourcePluginId: SOURCE_PLUGIN_ID
      });

      expect(showCollectSettingsMigrationModal).toHaveBeenCalledWith(expect.objectContaining({ sourcePluginName: 'Consistent Attachments and Links' }));
    });

    it('should fall back to the id when the proposing plugin is not installed', async () => {
      vi.mocked(showCollectSettingsMigrationModal).mockResolvedValue(null);

      await createMigratingPluginApi().migrateSettings({
        proposedSettings: { shouldCollectAttachmentsAutomatically: true },
        sourcePluginId: SOURCE_PLUGIN_ID
      });

      expect(showCollectSettingsMigrationModal).toHaveBeenCalledWith(expect.objectContaining({ sourcePluginName: SOURCE_PLUGIN_ID }));
    });

    it('should show one dialog at a time, so two proposals do not stack dialogs', async () => {
      const openDialogs: string[] = [];
      let releaseFirstDialog: () => void = noop;
      const firstDialogClosed = new Promise<void>((resolve) => {
        releaseFirstDialog = resolve;
      });

      vi.mocked(showCollectSettingsMigrationModal).mockImplementation(
        async (params: ShowCollectSettingsMigrationModalParams): Promise<null | SettingsMigrationRow[]> => {
          openDialogs.push(params.sourcePluginName);
          if (openDialogs.length === 1) {
            await firstDialogClosed;
          }
          return null;
        }
      );

      const pluginApiUnderTest = createMigratingPluginApi();
      const firstMigration = pluginApiUnderTest.migrateSettings({
        proposedSettings: { shouldCollectAttachmentsAutomatically: true },
        sourcePluginId: 'first-plugin'
      });
      const secondMigration = pluginApiUnderTest.migrateSettings({
        proposedSettings: { attachmentUnitFolderPaths: ['Pages'] },
        sourcePluginId: 'second-plugin'
      });

      await vi.waitFor(() => {
        // The second proposal is still waiting: its dialog has not been opened.
        expect(openDialogs).toEqual(['first-plugin']);
      });

      releaseFirstDialog();
      await Promise.all([firstMigration, secondMigration]);

      expect(openDialogs).toEqual(['first-plugin', 'second-plugin']);
    });
  });
});
