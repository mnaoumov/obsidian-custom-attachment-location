import type { TextFileView } from 'obsidian';

import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { installReleasedPlugin } from '../scripts/helpers/download-released-plugin.ts';
import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * Issue #65 asks for an image pasted into an Excalidraw drawing to get this plugin's file name, `{{prompt}}`
 * included. This suite pastes one through the REAL Excalidraw and pins what happens to it.
 *
 * Excalidraw saves a pasted image itself: it asks `fileManager.getAvailablePathForAttachment` for
 * `Pasted Image <date>.png`, keeps only the folder this plugin resolves, and writes its own name into it with
 * `vault.createBinary`. So the paste is another plugin's attachment, and `renameAttachmentsCreatedByOtherPluginsMode`
 * is the switch that governs it. Two things used to stop that switch from ever reaching it, and each phase
 * below exercises one:
 *
 *   - the resolver CLAIMED the path it handed Excalidraw as this plugin's own write, although the name in it was
 *     Excalidraw's;
 *   - the handler resolved templates only against a file `isNoteEx` calls a note, and a drawing is listed in
 *     `treatAsAttachmentExtensions` by default.
 *
 * The reason once given for keeping it that way was that compression hides the drawing's reference from
 * Obsidian. It does not: Excalidraw writes each image as a plain `<fileId>: [[path]]` line under
 * `## Embedded Files`, outside the `compressed-json` block, so the metadata cache indexes it and `renameFile`
 * rewrites it. The open drawing follows as well, because its in-memory record of the image holds the `TFile`
 * and serializes the link from it — which is why the suite saves the drawing AGAIN after the rename and reads
 * the line once more.
 *
 * Excalidraw ships with compression on and this suite keeps its defaults, so the drawings here are the
 * compressed kind the old reasoning was about.
 *
 * Both plugins are real. Excalidraw is its pinned RELEASE, written into the vault's plugin folder and enabled
 * with `enablePlugin` (never `enablePluginAndSave`, since the vault is shared by every suite) and removed again
 * at the end; Advanced Rename and Delete Handler is the one every vault is seeded with, which is what lists
 * `.excalidraw.md` as an attachment.
 */

const EXCALIDRAW_PLUGIN_ID = 'obsidian-excalidraw-plugin';
const EXCALIDRAW_REPO = 'zsviczian/obsidian-excalidraw-plugin';
const EXCALIDRAW_VERSION = '2.27.3';

// A 1x1 PNG: the smallest image Excalidraw accepts as a paste.
const PNG_DATA_URL = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';

interface ExcalidrawApiLike {
  addElementsToView: (shouldRepositionToCursor: boolean, shouldSave: boolean) => Promise<boolean>;
  addImage: (topX: number, topY: number, imageFile: string) => Promise<string>;
  addRect: (topX: number, topY: number, width: number, height: number) => string;
  create: (params: ExcalidrawCreateParams) => Promise<string>;
  reset: () => void;
  setView: (view: unknown) => unknown;
}

interface ExcalidrawCreateParams {
  readonly filename: string;
  readonly foldername: string;
  readonly onNewPane: boolean;
}

interface ExcalidrawPluginLike {
  readonly settings?: unknown;
}

// Excalidraw's view is a `TextFileView` whose `save` takes a second flag that forces the write.
interface ExcalidrawViewLike extends TextFileView {
  save: (shouldPreventReload?: boolean, shouldForceSave?: boolean) => Promise<void>;
}

interface ExcalidrawWindow extends Window {
  ExcalidrawAutomate?: ExcalidrawApiLike;
}

interface PasteResult {
  readonly drawingText: string;
  readonly drawingTextAfterSecondSave: string;
  readonly imagePath: string;
  readonly unresolvedLinkCount: number;
}

interface ProbeResult {
  readonly controlPaste: null | PasteResult;
  readonly drawingPath: string;
  readonly isExcalidrawLoaded: boolean;
  readonly renamedPaste: null | PasteResult;
  readonly settingsFound: boolean;
}

interface ScopedSettings {
  attachmentFolderPath: string;
  generatedAttachmentFileName: string;
  renameAttachmentsCreatedByOtherPluginsMode: string;
}

describe('An image pasted into an Excalidraw drawing (issue #65)', () => {
  it('gets the generated name, and the drawing keeps showing it through the rename and a later save', async () => {
    const vaultPath = getTemporaryVault().path;
    // Almost 5 MB of `main.js`, so it is written from Node rather than handed to the closure.
    await installReleasedPlugin({ pluginId: EXCALIDRAW_PLUGIN_ID, repo: EXCALIDRAW_REPO, vaultPath, version: EXCALIDRAW_VERSION });

    const result = await evalInObsidian({
      async callback({ app, excalidrawPluginId, findPluginSettingsComponent: findSettingsComponent, pngDataUrl }): Promise<ProbeResult> {
        // Module-scope constants are not captured by the serialized closure, so they live here.
        const WAIT_TIMEOUT_IN_MILLISECONDS = 15_000;
        const POLL_INTERVAL_IN_MILLISECONDS = 200;
        const SETTLE_DELAY_IN_MILLISECONDS = 2000;

        function isScopedSettings(value: unknown): value is ScopedSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['renameAttachmentsCreatedByOtherPluginsMode'] === 'string'
            && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isScopedSettings);
        if (!settingsComponent) {
          return { controlPaste: null, drawingPath: '', isExcalidrawLoaded: false, renamedPaste: null, settingsFound: false };
        }

        const originalSettings = {
          attachmentFolderPath: settingsComponent.settings.attachmentFolderPath,
          generatedAttachmentFileName: settingsComponent.settings.generatedAttachmentFileName,
          renameAttachmentsCreatedByOtherPluginsMode: settingsComponent.settings.renameAttachmentsCreatedByOtherPluginsMode
        };

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folderPath = `pasted-into-drawing-${stamp}`;
        const pathsBeforeSuite = new Set(app.vault.getAllLoadedFiles().map((file) => file.path));

        /*
         * Waits until `isDone` holds, and says which wait ran out rather than letting a later assertion report a
         * missing file as if the plugin had moved it somewhere else.
         */
        async function waitFor(description: string, isDone: () => Promise<boolean>): Promise<void> {
          const deadline = Date.now() + WAIT_TIMEOUT_IN_MILLISECONDS;
          while (!await isDone()) {
            if (Date.now() >= deadline) {
              throw new Error(`timed out waiting for ${description}`);
            }
            await sleep(POLL_INTERVAL_IN_MILLISECONDS);
          }
        }

        async function readText(path: string): Promise<string> {
          const file = app.vault.getFileByPath(path);
          return file ? await app.vault.read(file) : '';
        }

        async function paste(ea: ExcalidrawApiLike, view: ExcalidrawViewLike, drawingPath: string, isRenameExpected: boolean): Promise<PasteResult> {
          const pngPathsBefore = new Set(app.vault.getFiles().filter((file) => file.extension === 'png').map((file) => file.path));
          function getNewPngPaths(): string[] {
            return app.vault.getFiles().filter((file) => file.extension === 'png' && !pngPathsBefore.has(file.path)).map((file) => file.path);
          }

          ea.reset();
          ea.setView(view);
          await ea.addImage(0, 0, pngDataUrl);
          await ea.addElementsToView(false, true);
          // Excalidraw writes a pasted image into the vault on SAVE, which is where the foreign write happens.
          await view.save(false, true);

          await waitFor('the pasted image to be written', () => Promise.resolve(getNewPngPaths().length === 1));
          if (isRenameExpected) {
            await waitFor('the pasted image to be renamed', () => Promise.resolve(getNewPngPaths().some((path) => !path.includes('Pasted Image'))));
            const [renamedPath = ''] = getNewPngPaths();
            const renamedName = renamedPath.slice(renamedPath.lastIndexOf('/') + 1);
            await waitFor('the drawing to link the renamed image', async () => {
              const text = await readText(drawingPath);
              return text.includes(`[[${renamedName}]]`);
            });
          } else {
            // Nothing should happen, and absence cannot be polled for: give the handler its whole window to act.
            await sleep(SETTLE_DELAY_IN_MILLISECONDS);
          }

          const [imagePath = ''] = getNewPngPaths();
          const drawingText = await readText(drawingPath);

          // Save the drawing again, as the next edit would. Excalidraw writes the line from its own in-memory record.
          ea.reset();
          ea.setView(view);
          ea.addRect(0, 0, 10, 10);
          await ea.addElementsToView(false, true);
          await view.save(false, true);
          await sleep(SETTLE_DELAY_IN_MILLISECONDS);

          return {
            drawingText,
            drawingTextAfterSecondSave: await readText(drawingPath),
            imagePath,
            unresolvedLinkCount: Object.keys(app.metadataCache.unresolvedLinks[drawingPath] ?? {}).length
          };
        }

        try {
          await app.plugins.loadManifests();
          await app.plugins.enablePlugin(excalidrawPluginId);
          /*
           * Excalidraw finishes loading after `enablePlugin` resolves: its automation API exists before its settings
           * do, and `create` reads them. Asking too early throws inside Excalidraw, so wait for both.
           */
          await waitFor('Excalidraw to finish loading', () =>
            Promise.resolve(
              (window as ExcalidrawWindow).ExcalidrawAutomate !== undefined
                && (app.plugins.getPlugin(excalidrawPluginId) as ExcalidrawPluginLike | null)?.settings !== undefined
            ));
          const ea = (window as ExcalidrawWindow).ExcalidrawAutomate;
          if (!ea) {
            return { controlPaste: null, drawingPath: '', isExcalidrawLoaded: false, renamedPaste: null, settingsFound: true };
          }

          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = './assets/{{noteFileName}}';
            settings.generatedAttachmentFileName = `renamed-${stamp}`;
            // The enum's values ARE the display strings; this code runs inside Obsidian and cannot import them.
            settings.renameAttachmentsCreatedByOtherPluginsMode = 'None';
          });

          await app.vault.createFolder(folderPath);
          ea.reset();
          const drawingPath = await ea.create({ filename: `drawing-${stamp}`, foldername: folderPath, onNewPane: false });
          await waitFor('the drawing to open in Excalidraw', () => Promise.resolve(app.workspace.getLeavesOfType('excalidraw').some((leaf) => (leaf.view as ExcalidrawViewLike).file?.path === drawingPath)));
          const leaf = app.workspace.getLeavesOfType('excalidraw').find((candidate) => (candidate.view as ExcalidrawViewLike).file?.path === drawingPath);
          const view = leaf?.view as ExcalidrawViewLike;

          // The control: with the switch off, the paste keeps Excalidraw's own name, so the rename below is the switch's doing.
          const controlPaste = await paste(ea, view, drawingPath, false);

          await settingsComponent.editAndSave((settings) => {
            settings.renameAttachmentsCreatedByOtherPluginsMode = 'All';
          });
          const renamedPaste = await paste(ea, view, drawingPath, true);

          leaf?.detach();
          return { controlPaste, drawingPath, isExcalidrawLoaded: true, renamedPaste, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = originalSettings.attachmentFolderPath;
            settings.generatedAttachmentFileName = originalSettings.generatedAttachmentFileName;
            settings.renameAttachmentsCreatedByOtherPluginsMode = originalSettings.renameAttachmentsCreatedByOtherPluginsMode;
          });

          for (const leaf of app.workspace.getLeavesOfType('excalidraw')) {
            leaf.detach();
          }
          await app.plugins.disablePlugin(excalidrawPluginId);

          // Everything this suite or Excalidraw added to the vault, deepest first so a folder is empty when its turn comes.
          const addedPaths = app.vault.getAllLoadedFiles().map((file) => file.path).filter((path) => !pathsBeforeSuite.has(path));
          for (const path of addedPaths.sort((a, b) => b.length - a.length)) {
            const file = app.vault.getAbstractFileByPath(path);
            if (file) {
              await app.fileManager.trashFile(file);
            }
          }

          const pluginFolderPath = `${app.vault.configDir}/plugins/${excalidrawPluginId}`;
          if (await app.vault.adapter.exists(pluginFolderPath)) {
            await app.vault.adapter.rmdir(pluginFolderPath, true);
          }
          // So the removed plugin stops appearing in `app.plugins.manifests` for every later suite.
          await app.plugins.loadManifests();
        }
      },
      input: { excalidrawPluginId: EXCALIDRAW_PLUGIN_ID, findPluginSettingsComponent, pngDataUrl: PNG_DATA_URL },
      vaultPath
    });

    expect(result.settingsFound).toBe(true);
    expect(result.isExcalidrawLoaded).toBe(true);

    const drawingFolder = result.drawingPath.slice(0, result.drawingPath.lastIndexOf('/'));
    const drawingFileName = result.drawingPath.slice(result.drawingPath.lastIndexOf('/') + 1, -'.md'.length);

    // With the switch off, the image stays exactly as Excalidraw named it.
    expect(result.controlPaste?.imagePath).toMatch(/\/Pasted Image [^/]+\.png$/);

    /*
     * With it on, the image carries this plugin's generated name, in the folder the drawing's own template
     * resolves to — the same folder Excalidraw was handed for it.
     */
    const renamedPaste = result.renamedPaste;
    const expectedFolder = `${drawingFolder}/assets/${drawingFileName}`;
    expect(renamedPaste?.imagePath.startsWith(`${expectedFolder}/renamed-`)).toBe(true);
    const renamedName = renamedPaste?.imagePath.slice(expectedFolder.length + 1) ?? '';

    // The drawing links the new name, and a drawing that later saves itself does not put the old one back.
    expect(renamedPaste?.drawingText).toContain(`[[${renamedName}]]`);
    expect(renamedPaste?.drawingTextAfterSecondSave).toContain(`[[${renamedName}]]`);
    expect(renamedPaste?.drawingTextAfterSecondSave).toContain('```compressed-json');
    // Only the control's image is still called `Pasted Image`; nothing in the drawing points at a missing file.
    expect(renamedPaste?.drawingTextAfterSecondSave.match(/\[\[Pasted Image /g)?.length).toBe(1);
    expect(renamedPaste?.unresolvedLinkCount).toBe(0);
  }, 180_000);
});
