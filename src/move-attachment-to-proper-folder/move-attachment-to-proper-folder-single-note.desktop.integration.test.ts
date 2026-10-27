import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * Desktop coverage for "Move attachment to proper folder" on an attachment used by exactly ONE note — the
 * common case, and the one the command did nothing at all for: the list of notes to copy into was filled only
 * by the multiple-notes handling, so a single backlink left it empty and the command returned having moved
 * nothing, edited nothing and said nothing. Its unit test asserted exactly that, which is why it stayed green.
 *
 * Scenario, with the vault's default pattern `./assets/{{noteFileName}}`: an attachment sits in a stray folder
 * and one root note embeds it. Running the command on the attachment must leave it under the note's attachment
 * folder, point the note's embed at the new path, and remove the original.
 */

interface ProbeResult {
  readonly backlinkCount: number;
  readonly isCommandOffered: boolean;
  readonly isOriginalGone: boolean;
  readonly movedPaths: readonly string[];
  readonly noteContent: string;
  readonly noteFileName: string;
}

describe('Move attachment to proper folder — an attachment used by a single note', () => {
  it('moves the attachment into the note\'s attachment folder and updates the note\'s embed', async () => {
    const result = await evalInObsidian({
      async callback({ app, moveCommandId }): Promise<ProbeResult> {
        interface AvailabilityCheckableCommand {
          checkCallback?: (isChecking: boolean) => boolean | undefined;
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const strayFolderPath = `stray-${stamp}`;
        const attachmentPath = `${strayFolderPath}/pic-${stamp}.png`;
        const noteFileName = `move-note-${stamp}`;

        await app.vault.createFolder(strayFolderPath);
        const attachmentFile = await app.vault.createBinary(attachmentPath, new ArrayBuffer(4));
        const note = await app.vault.create(`${noteFileName}.md`, `![[${attachmentPath}]]\n`);

        // Wait for the metadata cache to resolve the embed, so the command sees its one backlink.
        let backlinkCount = 0;
        const resolveDeadline = Date.now() + 2000;
        while (Date.now() < resolveDeadline) {
          backlinkCount = app.metadataCache.getBacklinksForFile(attachmentFile).keys().length;
          if (backlinkCount >= 1) {
            break;
          }
          await sleep(100);
        }

        // The palette command acts on the ACTIVE file, and `openFile` resolves before the switch lands.
        await app.workspace.getLeaf(false).openFile(attachmentFile);
        const activeDeadline = Date.now() + 2000;
        while (Date.now() < activeDeadline && app.workspace.getActiveFile()?.path !== attachmentPath) {
          await sleep(100);
        }

        const commandUnknown: unknown = app.commands.commands[moveCommandId];
        const isCommandOffered = (commandUnknown as AvailabilityCheckableCommand | undefined)?.checkCallback?.(true) === true;

        app.commands.executeCommandById(moveCommandId);

        // The move runs inside a progress loop; poll until the original leaves its path.
        const moveDeadline = Date.now() + 6000;
        while (Date.now() < moveDeadline && app.vault.getFileByPath(attachmentPath)) {
          await sleep(200);
        }
        // The link edit is the last step before the delete, but give the note's write a moment to land.
        await sleep(300);

        return {
          backlinkCount,
          isCommandOffered,
          isOriginalGone: !app.vault.getFileByPath(attachmentPath),
          movedPaths: app.vault.getFiles().map((file) => file.path).filter((path) => path.startsWith(`assets/${noteFileName}/`)),
          noteContent: await app.vault.read(note),
          noteFileName
        };
      },
      input: {
        moveCommandId: 'obsidian-custom-attachment-location:move-attachment-to-proper-folder'
      },
      vaultPath: getTemporaryVault().path
    });

    // The scenario really staged one backlink, and the command was offered on the attachment.
    expect(result.backlinkCount).toBe(1);
    expect(result.isCommandOffered).toBe(true);

    // The attachment moved: exactly one file now sits in the note's attachment folder, and the original is gone.
    expect(result.movedPaths).toHaveLength(1);
    expect(result.movedPaths[0]).toMatch(/\.png$/);
    expect(result.isOriginalGone).toBe(true);

    // The note's embed follows it.
    const movedPath = result.movedPaths[0] ?? '';
    expect(result.noteContent).toContain(movedPath.split('/').pop() ?? movedPath);
    expect(result.noteContent).not.toContain('stray-');
  }, 60_000);
});
