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
 * version-sensitive Obsidian internals. The sibling
 * `collect-attachments-exclusion.desktop.integration.test.ts` is desktop-only for the same reason.
 */

/**
 * What following the orphan's link out of the confirmation dialog did (#87).
 */
interface LinkProbeResult {
  readonly hasMinimizeButton: boolean;
  readonly isMinimizedByLink: boolean;
  readonly isOrphanLinked: boolean;
  readonly isOrphanOpenedByLink: boolean;
}

interface ProbeResult extends LinkProbeResult {
  readonly commandDispatched: boolean;
  readonly modalShown: boolean;
  /**
   * Whatever the plugin put on screen while the confirmation modal was being waited for.
   *
   * `modalShown: false` on its own says only that nothing appeared, which is the least useful form of
   * this failure. The plugin reports "nothing to delete" as a notice rather than a dialog, so carrying
   * the notices into the assertion distinguishes "the command declined" from "the command never ran".
   */
  readonly noticeTexts: readonly string[];
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
        /*
         * The deadline loops in this closure run one after another and total at most 22s, under the transport's
         * ~30s per-closure default. The project raises its command timeout past that, but only as a backstop:
         * spent, it would kill the call as a bare transport timeout during the third loop, and the fourth —
         * the one this test is about — would never get to report. Each waits for something that happens
         * within moments on a quiet machine.
         */
        const resolveDeadline = Date.now() + 4000;
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

        /*
         * Two preconditions the command silently no-ops on, each of which shows up as "the confirmation
         * modal never appeared" rather than as anything nameable:
         *
         * - The active file is not this note yet. `openFile` resolves before the workspace has finished
         *   Switching, and the command reads `getActiveFile()`.
         * - The metadata cache still has work queued. Until the three attachments are indexed the plugin
         *   Sees nothing unused, reports "nothing to delete" and never opens a modal.
         */
        const activeDeadline = Date.now() + 4000;
        while (Date.now() < activeDeadline && app.workspace.getActiveFile()?.path !== note.path) {
          await sleep(100);
        }
        await new Promise<void>((resolve) => {
          app.metadataCache.onCleanCache(resolve);
        });

        const noticeTexts = new Set<string>();
        const noticeObserver = new MutationObserver(() => {
          for (const noticeEl of document.querySelectorAll('.notice')) {
            noticeTexts.add(noticeEl.textContent);
          }
        });
        noticeObserver.observe(document.body, { characterData: true, childList: true, subtree: true });

        const isCommandDispatched = app.commands.executeCommandById('obsidian-custom-attachment-location:delete-unused-attachments-in-file');

        /*
         * Drive the real confirmation modal: wait for it, follow the orphan's link out of it (#87), then click
         * its OK button. OK is clicked while the dialog is set aside, which is the path a user who went to
         * look takes when they come back through the minimized bar.
         */
        async function followOrphanLink(okButton: Element): Promise<LinkProbeResult> {
          const modalContainerEl = okButton.closest<HTMLElement>('.modal-container');
          const orphanLinkEl = [...modalContainerEl?.querySelectorAll('a') ?? []].find((aEl) => aEl.textContent === orphanPath);
          orphanLinkEl?.click();
          // Minimizing hides the container, backdrop and all, rather than removing it.
          const isMinimizedByLink = modalContainerEl?.style.display === 'none';
          const openDeadline = Date.now() + 2000;
          while (Date.now() < openDeadline && app.workspace.getActiveFile()?.path !== orphanPath) {
            await sleep(100);
          }
          return {
            hasMinimizeButton: Boolean(modalContainerEl?.querySelector('.minimize-button')),
            isMinimizedByLink,
            isOrphanLinked: Boolean(orphanLinkEl),
            isOrphanOpenedByLink: app.workspace.getActiveFile()?.path === orphanPath
          };
        }

        let isModalShown = false;
        let linkProbeResult: LinkProbeResult = {
          hasMinimizeButton: false,
          isMinimizedByLink: false,
          isOrphanLinked: false,
          isOrphanOpenedByLink: false
        };
        const modalDeadline = Date.now() + 6000;
        while (Date.now() < modalDeadline) {
          const okButton = document.querySelector('.modal-container .ok-button');
          if (okButton) {
            isModalShown = true;
            linkProbeResult = await followOrphanLink(okButton);
            (okButton as HTMLElement).click();
            break;
          }
          await sleep(200);
        }

        // The trash runs on the plugin's internal queue; poll until the orphan leaves the vault.
        const trashDeadline = Date.now() + 6000;
        while (Date.now() < trashDeadline) {
          if (!app.vault.getFileByPath(orphanPath)) {
            break;
          }
          await sleep(200);
        }

        noticeObserver.disconnect();

        return {
          ...linkProbeResult,
          commandDispatched: isCommandDispatched,
          modalShown: isModalShown,
          noticeTexts: [...noticeTexts],
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

    // The confirmation modal was really shown and driven through the DOM. On failure the message
    // Carries what the plugin did instead, which a bare `false` never could.
    expect(
      result.modalShown,
      `no confirmation modal; command dispatched: ${String(result.commandDispatched)}; notices: ${JSON.stringify(result.noticeTexts)}`
    ).toBe(true);

    // #87: the dialog can be set aside, and what it lists can be opened from it.
    expect(result.hasMinimizeButton).toBe(true);
    expect(result.isOrphanLinked).toBe(true);
    expect(result.isMinimizedByLink).toBe(true);
    expect(result.isOrphanOpenedByLink).toBe(true);

    // Only the genuinely-unused attachment is trashed; the referenced and shared ones survive.
    expect(result.orphanTrashed).toBe(true);
    expect(result.referencedSurvived).toBe(true);
    expect(result.sharedSurvived).toBe(true);
  }, 120_000);
});
