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
 * End-to-end coverage for issue #90: an Excalidraw drawing saved as a PLAIN `.md` is an attachment by its
 * `excalidraw-plugin` property, not only a `.excalidraw.md` by its name.
 *
 * This plugin holds no copy of that rule. It asks Advanced Rename and Delete Handler's published
 * `isTreatedAsAttachment(path)`, which learned property entries in 2.1.0, so what needs proving is the seam: the
 * REAL seeded handler, answering from its own `treatAsAttachmentExtensions`, through this plugin's `isNoteEx`,
 * into the sweep #83 is about. No stub is parked on the read-back ref.
 *
 * `Delete unused attachments in entire vault` spares an attachment unit folder that holds a real note with
 * something written in it. Two units nothing outside references are staged in one sweep, identical except for
 * the property:
 *
 * - `drawing_files/page.md` carries `excalidraw-plugin: parsed`, so it is an attachment and the unit goes whole.
 * - `note_files/page.md` does not, so it is a note and its unit stays. This is the control: without it, a
 *   sweep that trashed every unit would pass too.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const DELETE_COMMAND_ID = 'obsidian-custom-attachment-location:delete-unused-attachments-entire-vault';
/*
 * Under the transport's ~30s per-closure cap, not at it: several waits share one closure, and each step lands in
 * well under a second in a small temp vault.
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 5000;

interface ProbeResult {
  readonly confirmText: string;
  readonly handlerVersion: string;
  readonly isControlNoteTreatedAsAttachment: boolean;
  readonly isDrawingTreatedAsAttachment: boolean;
  readonly isDrawingUnitGone: boolean;
  readonly isNoteUnitAlive: boolean;
  readonly settingsFound: boolean;
}

describe('A drawing marked by its excalidraw-plugin property is an attachment (issue #90)', () => {
  it('trashes the unit folder of a property-marked drawing, and spares the one holding a real note', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        deleteCommandId,
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

        interface HandlerApiLike {
          isTreatedAsAttachment: (path: string) => boolean;
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
            && typeof (value as Record<string, unknown>)['isAttachmentUnitFolder'] === 'function'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        // The handler's own published API, read where every plugin bundle in the renderer shares it.
        function findHandlerApi(): HandlerApiLike | null {
          const registryState = (window as Partial<ObsidianDevUtilsWrapper>).__obsidianDevUtils;
          const api = registryState?.pluginApiRegistry?.value?.records?.[handlerPluginId]?.find((candidate) => !candidate.isRevoked)?.api;
          const record = api as null | Record<string, unknown> | undefined;
          return record && typeof record['isTreatedAsAttachment'] === 'function' ? api as HandlerApiLike : null;
        }

        const EMPTY_RESULT: ProbeResult = {
          confirmText: '',
          handlerVersion: '',
          isControlNoteTreatedAsAttachment: true,
          isDrawingTreatedAsAttachment: false,
          isDrawingUnitGone: false,
          isNoteUnitAlive: false,
          settingsFound: false
        };

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isUnitFolderSettings);
        const handlerApi = findHandlerApi();
        if (!settingsComponent || !handlerApi) {
          return EMPTY_RESULT;
        }

        const priorFolderPath = settingsComponent.settings.attachmentFolderPath;
        const priorUnitFolderPaths = settingsComponent.settings.attachmentUnitFolderPaths;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const noteName = `epu-note-${stamp}`;
        const notePath = `${noteName}.md`;
        const rootFolderPath = 'epu-assets';
        const attachmentFolderPath = `${rootFolderPath}/${noteName}`;

        const drawingUnitPath = `${attachmentFolderPath}/drawing_files`;
        const drawingPath = `${drawingUnitPath}/page.md`;
        const drawingImagePath = `${drawingUnitPath}/img.png`;

        const noteUnitPath = `${attachmentFolderPath}/note_files`;
        const controlNotePath = `${noteUnitPath}/page.md`;
        const noteImagePath = `${noteUnitPath}/img.png`;

        // The sweep trashes on its own queue, so an entry may already be gone by the time cleanup reaches it.
        async function trashIfExists(path: string): Promise<void> {
          const existing = app.vault.getAbstractFileByPath(path);
          if (!existing) {
            return;
          }
          try {
            await app.fileManager.trashFile(existing);
          } catch {
            // Removed between the lookup and the trash, which is the outcome this wanted anyway.
          }
        }

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = `./${rootFolderPath}/{{noteFileName}}`;
            settings.attachmentUnitFolderPaths = [drawingUnitPath, noteUnitPath];
          });

          await app.vault.createFolder(rootFolderPath);
          await app.vault.createFolder(attachmentFolderPath);
          await app.vault.createFolder(drawingUnitPath);
          await app.vault.createFolder(noteUnitPath);
          await app.vault.createBinary(drawingImagePath, new ArrayBuffer(4));
          await app.vault.createBinary(noteImagePath, new ArrayBuffer(4));

          // The same text in both, so the property is the only difference the sweep can see.
          const body = '# Excalidraw Data\n\n## Embedded Files\n4f1e2a: [[img.png]]\n';
          await app.vault.create(drawingPath, `---\nexcalidraw-plugin: parsed\n---\n\n${body}`);
          await app.vault.create(controlNotePath, body);

          // The note owning the attachment folder references neither unit.
          await app.vault.create(notePath, 'A note whose attachment folder holds two unit folders.\n');

          /*
           * A property entry matches a file only once the metadata cache has read it: before that the file is a
           * note, which is the conservative side. Waiting here keeps this test about the rule, not the race.
           */
          await waitUntil({
            message: 'the drawing\'s excalidraw-plugin property was not indexed',
            predicate: () => {
              const drawingFile = app.vault.getFileByPath(drawingPath);
              return drawingFile !== null && app.metadataCache.getFileCache(drawingFile)?.frontmatter?.['excalidraw-plugin'] === 'parsed';
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          await new Promise<void>((resolve) => {
            app.metadataCache.onCleanCache(resolve);
          });

          const isDrawingTreatedAsAttachment = handlerApi.isTreatedAsAttachment(drawingPath);
          const isControlNoteTreatedAsAttachment = handlerApi.isTreatedAsAttachment(controlNotePath);

          app.commands.executeCommandById(deleteCommandId);

          const confirmMarker = 'will be moved to the trash';
          function findConfirmContainer(): HTMLElement | null {
            return [...activeDocument.querySelectorAll<HTMLElement>('.modal-container')]
              .find((containerEl) => containerEl.textContent.includes(confirmMarker)) ?? null;
          }

          await waitUntil({
            message: 'the confirmation dialog never appeared',
            predicate: () => findConfirmContainer() !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const confirmContainerEl = findConfirmContainer();
          const confirmText = confirmContainerEl?.querySelector('.modal-content')?.textContent ?? '';

          // Confirm through the dialog's own button, so the queued operation's promise resolves.
          const buttonEls = [...confirmContainerEl?.querySelectorAll<HTMLButtonElement>('button') ?? []];
          const okButtonEl = buttonEls.find((buttonEl) => buttonEl.textContent === 'OK') ?? buttonEls[0];
          okButtonEl?.click();

          await waitUntil({
            message: 'the drawing\'s unit folder was never trashed',
            predicate: () => app.vault.getAbstractFileByPath(drawingUnitPath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          return {
            confirmText,
            handlerVersion: app.plugins.getPlugin(handlerPluginId)?.manifest.version ?? '',
            isControlNoteTreatedAsAttachment,
            isDrawingTreatedAsAttachment,
            isDrawingUnitGone: app.vault.getAbstractFileByPath(drawingUnitPath) === null,
            isNoteUnitAlive: app.vault.getAbstractFileByPath(controlNotePath) !== null && app.vault.getAbstractFileByPath(noteImagePath) !== null,
            settingsFound: true
          };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorFolderPath;
            settings.attachmentUnitFolderPaths = priorUnitFolderPaths;
          });
          /*
           * The whole tree in one trash, not file by file: trashing `note_files/page.md` on its own makes Obsidian's
           * main process log `Failed to parse path`, which the tree trash does not.
           */
          await trashIfExists(notePath);
          await trashIfExists(rootFolderPath);
        }
      },
      input: {
        deleteCommandId: DELETE_COMMAND_ID,
        findPluginSettingsComponent,
        handlerPluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound, 'the settings component or the handler\'s API was not found').toBe(true);

    // The preconditions: the real handler is the release that knows property entries, and it answers by them.
    expect(result.handlerVersion).toBe(ADVANCED_RENAME_AND_DELETE_HANDLER_VERSION);
    expect(result.isDrawingTreatedAsAttachment).toBe(true);
    expect(result.isControlNoteTreatedAsAttachment).toBe(false);

    // The drawing is an attachment, so nothing spares its unit.
    expect(result.isDrawingUnitGone).toBe(true);
    expect(result.confirmText).toContain('drawing_files');

    // The same file without the property is a note, and the unit holding it stays whole.
    expect(result.isNoteUnitAlive).toBe(true);
    expect(result.confirmText).not.toContain('note_files');
  }, 180_000);
});
