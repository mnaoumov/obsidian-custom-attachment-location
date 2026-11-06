import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for `Rename attachments in current note`: the note's attachments get the rename template's
 * names in the folder they already sit in, and the note's links follow, while an attachment another note links too
 * keeps its name. The template is set through `editAndSave`, with `{{sequenceNumber}}` so the two names are known in
 * advance, and restored afterwards.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const COMMAND_ID = `${PLUGIN_ID}:rename-attachments-in-file`;
// Under the transport's ~30s per-closure cap; each step is a vault write or a queued rename in a small vault.
const WAIT_TIMEOUT_IN_MILLISECONDS = 6000;

interface ProbeResult {
  readonly isCommandOffered: boolean;
  readonly noteContent: string;
  readonly paths: readonly string[];
  readonly probesFound: boolean;
  readonly stamp: string;
}

describe('Rename attachments in current note', () => {
  it('renames the note\'s own attachments in place, updates its links, and leaves a shared one alone', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        commandId,
        findPluginSettingsComponent: findSettingsComponent,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface AvailabilityCheckableCommand {
          readonly checkCallback?: (isChecking: boolean) => boolean | undefined;
        }

        interface RenameSettings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          manuallyRenamedAttachmentFileName: string;
        }

        function isRenameSettings(value: unknown): value is RenameSettings {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null && typeof record['manuallyRenamedAttachmentFileName'] === 'string';
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const settingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isRenameSettings);
        if (!settingsComponent) {
          return { isCommandOffered: false, noteContent: '', paths: [], probesFound: false, stamp };
        }

        const priorTemplate = settingsComponent.settings.manuallyRenamedAttachmentFileName;
        await settingsComponent.editAndSave((settings) => {
          settings.manuallyRenamedAttachmentFileName = `renamed-${stamp}-{{sequenceNumber}}`;
        });

        try {
          const folderPath = `rename-${stamp}`;
          await app.vault.createFolder(folderPath);
          await app.vault.createBinary(`${folderPath}/Pasted image.png`, new ArrayBuffer(4));
          await app.vault.createBinary(`${folderPath}/document.pdf`, new ArrayBuffer(4));
          const sharedFile = await app.vault.createBinary(`${folderPath}/shared.png`, new ArrayBuffer(4));
          const note = await app.vault.create(
            `${folderPath}/note.md`,
            `![[${folderPath}/Pasted image.png]]\n\n[[${folderPath}/document.pdf]]\n\n![[${folderPath}/shared.png]]\n`
          );
          await app.vault.create(`${folderPath}/other.md`, `![[${folderPath}/shared.png]]\n`);

          // The shared check reads backlinks, so wait until both notes are indexed as linking the shared file.
          await waitUntil({
            message: 'the shared attachment was not indexed as linked by both notes',
            predicate: () => app.metadataCache.getBacklinksForFile(sharedFile).keys().length === 2,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          // The palette command acts on the ACTIVE file, and `openFile` resolves before the switch lands.
          await app.workspace.getLeaf(false).openFile(note);
          await waitUntil({
            message: 'the note did not become the active file',
            predicate: () => app.workspace.getActiveFile() === note,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const commandUnknown: unknown = app.commands.commands[commandId];
          const isCommandOffered = (commandUnknown as AvailabilityCheckableCommand | undefined)?.checkCallback?.(true) === true;
          app.commands.executeCommandById(commandId);

          await waitUntil({
            message: 'the document was not renamed',
            predicate: () => app.vault.getFileByPath(`${folderPath}/document.pdf`) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });
          await waitUntil({
            message: 'the link to the document did not follow the rename',
            predicate: async () => {
              const noteContent = await app.vault.read(note);
              return noteContent.includes(`renamed-${stamp}-2.pdf`);
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          return {
            isCommandOffered,
            noteContent: await app.vault.read(note),
            paths: app.vault.getFiles().map((file) => file.path).filter((path) => path.startsWith(`${folderPath}/`)).sort(),
            probesFound: true,
            stamp
          };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.manuallyRenamedAttachmentFileName = priorTemplate;
          });
        }
      },
      input: {
        commandId: COMMAND_ID,
        findPluginSettingsComponent,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);
    expect(result.isCommandOffered).toBe(true);

    const folderPath = `rename-${result.stamp}`;
    // Both own attachments are renamed where they are; the shared one keeps its name; nothing moved folders.
    expect(result.paths).toStrictEqual([
      `${folderPath}/note.md`,
      `${folderPath}/other.md`,
      `${folderPath}/renamed-${result.stamp}-1.png`,
      `${folderPath}/renamed-${result.stamp}-2.pdf`,
      `${folderPath}/shared.png`
    ]);

    // The note's links follow the renames.
    expect(result.noteContent).toContain(`renamed-${result.stamp}-1.png`);
    expect(result.noteContent).toContain(`renamed-${result.stamp}-2.pdf`);
    expect(result.noteContent).not.toContain('Pasted image');
    expect(result.noteContent).toContain('shared.png');
  }, 60_000);
});
