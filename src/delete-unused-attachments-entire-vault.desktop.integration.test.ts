import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #64 (G97): `Delete unused attachments` over the WHOLE vault, not just
 * the current note.
 *
 * The scenario is the one that makes the vault-wide scope different from running the per-note command
 * on whichever note happens to be open: the orphan sits in a folder belonging to a note that is NOT
 * active, so only a sweep that reads every note can find it. A second attachment, still embedded, is
 * staged alongside it and must survive -- a sweep that deleted both would "pass" a test that only
 * looked for the orphan being gone.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const DELETE_COMMAND_ID = 'obsidian-custom-attachment-location:delete-unused-attachments-entire-vault';
/*
 * THREE of these run in sequence inside a single `evalInObsidian` callback, so their sum has to fit the
 * test's own 180s budget with room to spare. Sized generously: the trash step runs on the plugin's
 * internal queue behind whatever else is in flight, and cutting it too fine just converts a slow-but-
 * correct pass into "the orphan was never trashed".
 */
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;

interface ProbeResult {
  readonly confirmText: string;
  readonly isKeptAlive: boolean;
  readonly isOrphanGone: boolean;
  readonly settingsFound: boolean;
}

describe('Delete unused attachments in entire vault (issue #64)', () => {
  it('finds an orphan under a note that is not open, and spares one still embedded', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        deleteCommandId,
        lib: { waitUntil },
        pluginId,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        const SETTLE_DELAY_IN_MILLISECONDS = 1000;

        interface RemoverSettings {
          attachmentFolderPath: string;
        }

        function isRemoverSettings(value: unknown): value is RemoverSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        // The plugin does not expose its settings publicly, so locate the live settings object by
        // Walking the plugin's component tree.
        function findSettings(): null | RemoverSettings {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [app.plugins.getPlugin(pluginId)];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            if (isRemoverSettings(record['settings'])) {
              return record['settings'];
            }
            let values: unknown[] = [];
            if (Array.isArray(current)) {
              values = current;
            } else if (current instanceof Map) {
              values = [...current.values()];
            } else {
              for (const [key, value] of Object.entries(record)) {
                if (!block.has(key)) {
                  values.push(value);
                }
              }
            }
            for (const value of values) {
              if (value !== null && (typeof value === 'object' || typeof value === 'function')) {
                queue.push(value);
              }
            }
          }
          return null;
        }

        const foundSettings = findSettings();
        if (!foundSettings) {
          return { confirmText: '', isKeptAlive: false, isOrphanGone: false, settingsFound: false };
        }
        const settings: RemoverSettings = foundSettings;
        const priorFolderPath = settings.attachmentFolderPath;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const farNotePath = `duv-far-${stamp}.md`;
        const openNotePath = `duv-open-${stamp}.md`;
        const farFolder = `duv-assets/duv-far-${stamp}`;
        const orphanPath = `${farFolder}/orphan.png`;
        const keptPath = `${farFolder}/kept.png`;
        const createdPaths = [orphanPath, keptPath, farNotePath, openNotePath];

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone: the sweep trashes
         * entries on its own queue, and trashing one a second time throws `ENOENT` from the rename
         * into `.trash`.
         */
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
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './duv-assets/${noteFileName}';

          await app.vault.createFolder('duv-assets');
          await app.vault.createFolder(farFolder);
          await app.vault.createBinary(orphanPath, new ArrayBuffer(4));
          await app.vault.createBinary(keptPath, new ArrayBuffer(4));
          // The far note embeds only `kept.png`, so `orphan.png` is referenced by nothing.
          await app.vault.create(farNotePath, `![[${keptPath}]]\n`);
          const openNote = await app.vault.create(openNotePath, 'unrelated\n');

          // Open the OTHER note. The per-note command run here would find nothing at all; only a
          // Vault-wide sweep reaches the far note's attachment folder.
          await app.workspace.getLeaf(false).openFile(openNote);
          await sleep(SETTLE_DELAY_IN_MILLISECONDS);

          await waitUntil({
            message: 'the kept embed was not indexed',
            predicate: () => {
              const keptFile = app.vault.getFileByPath(keptPath);
              return keptFile !== null && app.metadataCache.getBacklinksForFile(keptFile).keys().length > 0;
            },
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          app.commands.executeCommandById(deleteCommandId);

          await waitUntil({
            message: 'the confirmation dialog never appeared',
            predicate: () => activeDocument.querySelector('.modal-content') !== null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          const confirmText = activeDocument.querySelector('.modal-content')?.textContent ?? '';

          // Confirm through the dialog's own button. Detaching the container would leave the queued
          // Operation's promise unresolved and block everything queued behind it.
          const buttonEls = [...activeDocument.querySelectorAll<HTMLButtonElement>(':scope .modal-content button')];
          const okButtonEl = buttonEls.find((buttonEl) => buttonEl.textContent === 'OK') ?? buttonEls[0];
          okButtonEl?.click();

          await waitUntil({
            message: 'the orphan was never trashed',
            predicate: () => app.vault.getAbstractFileByPath(orphanPath) === null,
            timeoutInMilliseconds: waitTimeoutInMilliseconds
          });

          return {
            confirmText,
            isKeptAlive: app.vault.getAbstractFileByPath(keptPath) !== null,
            isOrphanGone: app.vault.getAbstractFileByPath(orphanPath) === null,
            settingsFound: true
          };
        } finally {
          settings.attachmentFolderPath = priorFolderPath;
          for (const path of createdPaths) {
            await trashIfExists(path);
          }
          await trashIfExists(farFolder);
          await trashIfExists('duv-assets');
        }
      },
      input: {
        deleteCommandId: DELETE_COMMAND_ID,
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // The orphan lived under a note that was never open, which is the whole point of the new scope.
    expect(result.isOrphanGone).toBe(true);

    // And the still-embedded sibling survived, so the sweep is discriminating rather than thorough.
    expect(result.isKeptAlive).toBe(true);

    // The dialog leads with the count, which is the part a user can weigh when the list is long.
    expect(result.confirmText).toContain('1 attachment(s) will be moved to the trash.');
    expect(result.confirmText).toContain('orphan.png');
    expect(result.confirmText).not.toContain('kept.png');
  }, 180_000);
});
