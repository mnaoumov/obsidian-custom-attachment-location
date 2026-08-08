import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #23 (the delete half): the "Delete unused attachments in current note"
 * command / context-menu item trashes attachments in a note's attachment folder that the note no longer
 * references, while protecting attachments that are still referenced by the note OR by another note.
 *
 * The data-destructive path is driven through the REAL confirmation modal (the OK button is clicked in
 * the live DOM), not stubbed. Scenario, in the note `note-<stamp>`'s attachment folder
 * `assets/note-<stamp>/`:
 *   - `ref-<stamp>.png`    -> embedded in the note                 -> MUST survive;
 *   - `orphan-<stamp>.png` -> referenced by no note                -> MUST be trashed;
 *   - `shared-<stamp>.png` -> referenced only by `other-<stamp>.md` -> MUST survive (shared attachment).
 *
 * Desktop-only: the plugin is cross-platform (`isDesktopOnly: false`), but this run has no Android
 * emulator provisioned, and the delete flow is platform-agnostic vault/trash + modal DOM logic with no
 * version-sensitive Obsidian internals (see the G99 note in the tracking task). The sibling
 * `collect-attachments-exclusion.desktop.integration.test.ts` is desktop-only for the same reason.
 */

interface ProbeResult {
  readonly modalShown: boolean;
  readonly orphanTrashed: boolean;
  readonly refBacklinkCount: number;
  readonly referencedSurvived: boolean;
  readonly sharedBacklinkCount: number;
  readonly sharedSurvived: boolean;
}

describe('Delete unused attachments (issue #23)', () => {
  it('trashes only the genuinely-unused attachment, keeping referenced and shared ones', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<ProbeResult> {
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folderPath = `assets/note-${stamp}`;
        const notePath = `note-${stamp}.md`;
        const otherNotePath = `other-${stamp}.md`;
        const refPath = `${folderPath}/ref-${stamp}.png`;
        const orphanPath = `${folderPath}/orphan-${stamp}.png`;
        const sharedPath = `${folderPath}/shared-${stamp}.png`;

        await app.vault.createFolder(folderPath);
        const bytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer;
        await app.vault.createBinary(refPath, bytes);
        await app.vault.createBinary(orphanPath, bytes);
        await app.vault.createBinary(sharedPath, bytes);

        const note = await app.vault.create(notePath, `![[ref-${stamp}.png]]\n`);
        await app.vault.create(otherNotePath, `![[shared-${stamp}.png]]\n`);

        // Wait for the metadata cache to resolve both embeds so the plugin's backlink checks are accurate.
        const refFile = app.vault.getFileByPath(refPath);
        const sharedFile = app.vault.getFileByPath(sharedPath);
        let refBacklinkCount = 0;
        let sharedBacklinkCount = 0;
        const resolveDeadline = Date.now() + 8000;
        while (Date.now() < resolveDeadline) {
          refBacklinkCount = refFile ? app.metadataCache.getBacklinksForFile(refFile).keys().length : 0;
          sharedBacklinkCount = sharedFile ? app.metadataCache.getBacklinksForFile(sharedFile).keys().length : 0;
          if (refBacklinkCount >= 1 && sharedBacklinkCount >= 1) {
            break;
          }
          await sleep(200);
        }

        // The command targets the active file, mirroring what the note context-menu item does.
        await app.workspace.getLeaf(false).openFile(note);
        app.commands.executeCommandById('obsidian-custom-attachment-location:delete-unused-attachments-in-file');

        // Drive the real confirmation modal: wait for it, then click its OK button.
        let isModalShown = false;
        const modalDeadline = Date.now() + 12_000;
        while (Date.now() < modalDeadline) {
          const okButton = document.querySelector('.modal-container .ok-button');
          if (okButton) {
            isModalShown = true;
            (okButton as HTMLElement).click();
            break;
          }
          await sleep(200);
        }

        // The trash runs on the plugin's internal queue; poll until the orphan leaves the vault.
        const trashDeadline = Date.now() + 12_000;
        while (Date.now() < trashDeadline) {
          if (!app.vault.getFileByPath(orphanPath)) {
            break;
          }
          await sleep(200);
        }

        return {
          modalShown: isModalShown,
          orphanTrashed: !app.vault.getFileByPath(orphanPath),
          refBacklinkCount,
          referencedSurvived: Boolean(app.vault.getFileByPath(refPath)),
          sharedBacklinkCount,
          sharedSurvived: Boolean(app.vault.getFileByPath(sharedPath))
        };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    // The scenario really staged the two backlinks before the command ran.
    expect(result.refBacklinkCount).toBe(1);
    expect(result.sharedBacklinkCount).toBe(1);

    // The confirmation modal was really shown and driven through the DOM.
    expect(result.modalShown).toBe(true);

    // Only the genuinely-unused attachment is trashed; the referenced and shared ones survive.
    expect(result.orphanTrashed).toBe(true);
    expect(result.referencedSurvived).toBe(true);
    expect(result.sharedSurvived).toBe(true);
  }, 120_000);
});
