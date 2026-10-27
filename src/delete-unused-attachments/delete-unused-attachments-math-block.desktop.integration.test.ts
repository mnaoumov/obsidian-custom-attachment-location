import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * Issue #89: "Delete unused attachments in current note" trashed an image the note still embeds.
 *
 * Obsidian's own parser folds `![[image]]` into a math block that directly follows a list item (with a blank
 * line inside the formula), so the embed never reaches the metadata cache or the backlink index. The plugin
 * judged unused on the cache's word alone. It now also reads the note's text for links, so the embed keeps
 * the file.
 *
 * In the note's attachment folder `assets/note-<stamp>/`:
 *   - `kept-<stamp>.png`   -> embedded after the math block, invisible to the cache -> MUST survive;
 *   - `orphan-<stamp>.png` -> referenced by nothing                                -> MUST be trashed.
 *
 * The orphan is there so the command reaches its confirmation dialog: a run that trashes nothing would pass
 * the survival check without ever having judged anything.
 */

interface ProbeResult {
  readonly isCacheMissingEmbed: boolean;
  readonly isKeptSurvived: boolean;
  readonly isModalShown: boolean;
  readonly isOrphanTrashed: boolean;
  readonly listedTexts: readonly string[];
}

describe('Delete unused attachments after a math block that follows a list (#89)', () => {
  it('keeps an attachment the note embeds even when the metadata cache misses the embed', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<ProbeResult> {
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folderPath = `assets/note-${stamp}`;
        const notePath = `note-${stamp}.md`;
        const keptPath = `${folderPath}/kept-${stamp}.png`;
        const orphanPath = `${folderPath}/orphan-${stamp}.png`;

        await app.vault.createFolder(folderPath);
        const bytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer;
        await app.vault.createBinary(keptPath, bytes);
        await app.vault.createBinary(orphanPath, bytes);

        // The reporter's note, verbatim: the blank line inside the formula is what makes the parser misread it.
        const note = await app.vault.create(notePath, `- Item\n$$\nx\n\n$$\n![[kept-${stamp}.png]]\n`);

        await app.workspace.getLeaf(false).openFile(note);
        const activeDeadline = Date.now() + 4000;
        while (Date.now() < activeDeadline && app.workspace.getActiveFile()?.path !== note.path) {
          await sleep(100);
        }
        await new Promise<void>((resolve) => {
          app.metadataCache.onCleanCache(resolve);
        });

        // The precondition that makes this a repro rather than an ordinary delete.
        const keptFile = app.vault.getFileByPath(keptPath);
        const isCacheMissingEmbed = keptFile !== null && app.metadataCache.getBacklinksForFile(keptFile).keys().length === 0;

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
          isCacheMissingEmbed,
          isKeptSurvived: Boolean(app.vault.getFileByPath(keptPath)),
          isModalShown,
          isOrphanTrashed: !app.vault.getFileByPath(orphanPath),
          listedTexts
        };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(
      result.isCacheMissingEmbed,
      'the metadata cache indexed the embed, so this Obsidian no longer reproduces #89 and the test proves nothing'
    ).toBe(true);
    expect(result.isModalShown).toBe(true);
    expect(result.listedTexts).toHaveLength(1);
    expect(result.isOrphanTrashed).toBe(true);
    expect(result.isKeptSurvived).toBe(true);
  }, 120_000);
});
