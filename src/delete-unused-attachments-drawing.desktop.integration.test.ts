import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * An image only an Excalidraw drawing shows survives "Delete unused attachments", and this pins WHY.
 *
 * The sweep never scans a drawing as a note (it is treated as an attachment), so the only thing keeping such an
 * image alive is its backlink from the drawing. That backlink exists because Excalidraw writes each image a
 * drawing shows as a plain `<fileId>: [[path]]` line under `## Embedded Files`, OUTSIDE the `compressed-json`
 * block, which holds the scene JSON and no vault paths. Compression therefore hides nothing from the index.
 *
 * The layout whose data section opens with `%%` (Excalidraw keeps it once a file has it) looks as if it should
 * hide the line in a comment, but Obsidian indexes links inside a `%%` comment too. If either precondition below
 * ever stops holding, the sweep's backlink check is no longer enough for drawings and needs to read their text.
 *
 * In the note's attachment folder `assets/note-<stamp>/`:
 *   - `commented-<stamp>.png` -> shown only by a drawing whose data section is a `%%` comment -> MUST survive;
 *   - `plain-<stamp>.png`     -> shown only by a drawing in the default layout                -> MUST survive;
 *   - `orphan-<stamp>.png`    -> referenced by nothing                                         -> MUST be trashed.
 *
 * The drawings live outside the note's folder and outside anything the command was pointed at. The orphan is
 * there so the command reaches its confirmation dialog.
 */

interface ProbeResult {
  readonly isCommentedIndexed: boolean;
  readonly isCommentedSurvived: boolean;
  readonly isModalShown: boolean;
  readonly isOrphanTrashed: boolean;
  readonly isPlainIndexed: boolean;
  readonly isPlainSurvived: boolean;
  readonly listedTexts: readonly string[];
}

describe('Delete unused attachments keeps what a drawing shows', () => {
  it('keeps an image only a drawing embeds, compressed or commented out, through its backlink', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<ProbeResult> {
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folderPath = `assets/note-${stamp}`;
        const notePath = `note-${stamp}.md`;
        const commentedPath = `${folderPath}/commented-${stamp}.png`;
        const plainPath = `${folderPath}/plain-${stamp}.png`;
        const orphanPath = `${folderPath}/orphan-${stamp}.png`;
        const drawingsFolderPath = `drawings-${stamp}`;

        await app.vault.createFolder(folderPath);
        await app.vault.createFolder(drawingsFolderPath);
        const bytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer;
        await app.vault.createBinary(commentedPath, bytes);
        await app.vault.createBinary(plainPath, bytes);
        await app.vault.createBinary(orphanPath, bytes);

        // The shape Excalidraw's `generateMDBase` writes, with the scene JSON reduced to a stub.
        function drawingContent(isCommentedOut: boolean, imagePath: string): string {
          return [
            '---',
            'excalidraw-plugin: parsed',
            '---',
            '',
            isCommentedOut ? '%%\n# Excalidraw Data' : '# Excalidraw Data',
            '',
            '## Text Elements',
            '## Embedded Files',
            `4f1e2a: [[${imagePath}]]`,
            '',
            isCommentedOut ? '## Drawing' : '%%\n## Drawing',
            '```compressed-json',
            'N4KAkARALgngDgUwgLgAQQQDwMYEMA2AlgCYBOuA7hADTgQBuCpAzoQPYB2KqATLZMzYBXUtiRoIACyhQ4zZAHoFAc0JRJQgEYA6bGwC2CgF7N6hbEcK4OCtptbErHALRY8RMpWdx8Ha',
            '```',
            '%%',
            ''
          ].join('\n');
        }

        await app.vault.create(`${drawingsFolderPath}/commented-${stamp}.excalidraw.md`, drawingContent(true, commentedPath));
        await app.vault.create(`${drawingsFolderPath}/plain-${stamp}.excalidraw.md`, drawingContent(false, plainPath));
        const note = await app.vault.create(notePath, 'A note whose attachment folder holds images only drawings show.\n');

        await app.workspace.getLeaf(false).openFile(note);
        const activeDeadline = Date.now() + 4000;
        while (Date.now() < activeDeadline && app.workspace.getActiveFile()?.path !== note.path) {
          await sleep(100);
        }
        await new Promise<void>((resolve) => {
          app.metadataCache.onCleanCache(resolve);
        });

        function backlinkCount(path: string): number {
          const file = app.vault.getFileByPath(path);
          return file ? app.metadataCache.getBacklinksForFile(file).keys().length : -1;
        }
        // The two preconditions: both layouts give the image a backlink from its drawing.
        const isPlainIndexed = backlinkCount(plainPath) > 0;
        const isCommentedIndexed = backlinkCount(commentedPath) > 0;

        app.commands.executeCommandById('obsidian-custom-attachment-location:delete-unused-attachments-in-file');

        let isModalShown = false;
        let listedTexts: string[] = [];
        const modalDeadline = Date.now() + 6000;
        while (Date.now() < modalDeadline) {
          const okButton = document.querySelector<HTMLElement>('.modal-container .ok-button');
          if (okButton) {
            isModalShown = true;
            listedTexts = [...okButton.closest('.modal-container')?.querySelectorAll('li') ?? []].map((liEl) => liEl.textContent);
            okButton.click();
            break;
          }
          await sleep(200);
        }

        const trashDeadline = Date.now() + 6000;
        while (Date.now() < trashDeadline && app.vault.getFileByPath(orphanPath)) {
          await sleep(200);
        }

        return {
          isCommentedIndexed,
          isCommentedSurvived: Boolean(app.vault.getFileByPath(commentedPath)),
          isModalShown,
          isOrphanTrashed: !app.vault.getFileByPath(orphanPath),
          isPlainIndexed,
          isPlainSurvived: Boolean(app.vault.getFileByPath(plainPath)),
          listedTexts
        };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(result.isPlainIndexed, 'Obsidian no longer indexes a drawing\'s Embedded Files line').toBe(true);
    expect(
      result.isCommentedIndexed,
      'Obsidian no longer indexes a link inside a %% comment, so a commented-out drawing leaves its images without a backlink'
    ).toBe(true);
    expect(result.isModalShown).toBe(true);
    expect(result.listedTexts).toHaveLength(1);
    expect(result.isOrphanTrashed).toBe(true);
    expect(result.isPlainSurvived).toBe(true);
    expect(result.isCommentedSurvived).toBe(true);
  }, 120_000);
});
