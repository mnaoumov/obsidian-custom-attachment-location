import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #57 (the rescue half, G97): an attachment that a deletion would
 * otherwise strand is moved into the surviving note's attachment folder instead of being left behind.
 *
 * The scenario in every phase: `ar-img-<stamp>.png` sits in note A's attachment folder and is
 * embedded by BOTH note A and note B. Deleting A — or the folder A itself lives in — already leaves
 * the image alive (obsidian-dev-utils refuses to delete a still-used attachment), but until this
 * feature it was left sitting in a folder whose owning note is gone. The phases:
 *
 *   - `deletedNote`   — note A is deleted            -> the image lands in B's attachment folder;
 *   - `deletedFolder` — the folder holding A is deleted -> same, and the hook is called twice
 *                       (the folder walk, then A's own deletion re-walking its links), so it has to
 *                       be free of side effects;
 *   - `settingOff`    — the control: with the setting off the image stays exactly where it was;
 *   - `tie`           — two surviving notes and no `notePriorities` to rank them, which is an
 *                       ambiguity the user has not resolved, so the image stays put.
 *
 * Two things this test must NOT do, both learned the hard way in the dev-utils half:
 *
 *   - Do not assert on the surviving note's markdown. Obsidian rewrites the embed to its shortest
 *     unambiguous form, so the destination path never appears in the text. `resolvedLinks` is the
 *     observable that actually carries it.
 *   - Do not read the notice at the end. It auto-dismisses, so it is latched by a MutationObserver
 *     while the phase runs.
 *
 * Desktop-only: the plugin is cross-platform (`isDesktopOnly: false`), but this run has no Android
 * emulator provisioned, and the delete flow is platform-agnostic vault/trash logic with no
 * version-sensitive Obsidian internals — the same reason its siblings record.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const WAIT_TIMEOUT_IN_MILLISECONDS = 20_000;
const SETTLE_TIMEOUT_IN_MILLISECONDS = 5000;

interface PhaseResult {
  readonly attachmentPath: string;
  readonly isResolvedFromSurvivingNote: boolean;
  readonly noticeText: string;
}

interface ProbeResult {
  readonly deletedFolder: PhaseResult;
  readonly deletedNote: PhaseResult;
  readonly isSettingsFound: boolean;
  readonly settingOff: PhaseResult;
  readonly tie: PhaseResult;
}

describe('Rescuing a shared attachment from a deletion (issue #57)', () => {
  it('moves a still-referenced attachment into the surviving note attachment folder', async () => {
    const result = await evalInObsidian({
      async callback({
        app,
        lib: { waitUntil },
        pluginId,
        settleTimeoutInMilliseconds,
        waitTimeoutInMilliseconds
      }): Promise<ProbeResult> {
        interface PhaseParams {
          readonly isFolderDeleted: boolean;
          readonly notePriorities: readonly string[];
          readonly shouldAddTyingNote: boolean;
          readonly shouldRescueSharedAttachments: boolean;
        }

        interface RescueSettings {
          attachmentFolderPath: string;
          notePriorities: readonly string[];
          shouldDeleteOrphanAttachments: boolean;
          shouldRescueSharedAttachments: boolean;
        }

        function isRescueSettings(value: unknown): value is RescueSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldRescueSharedAttachments'] === 'boolean'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        // The plugin does not expose its settings publicly, so locate the live settings object
        // (the one the rescuer reads) by walking the plugin's component tree.
        function findSettings(): null | RescueSettings {
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
            if (isRescueSettings(record['settings'])) {
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

        const EMPTY_PHASE: PhaseResult = { attachmentPath: '', isResolvedFromSurvivingNote: false, noticeText: '' };

        const foundSettings = findSettings();
        if (!foundSettings) {
          return {
            deletedFolder: EMPTY_PHASE,
            deletedNote: EMPTY_PHASE,
            isSettingsFound: false,
            settingOff: EMPTY_PHASE,
            tie: EMPTY_PHASE
          };
        }
        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: RescueSettings = foundSettings;

        const priorFolderPath = settings.attachmentFolderPath;
        const priorPriorities = settings.notePriorities;
        const shouldDeleteOrphanAttachmentsPrior = settings.shouldDeleteOrphanAttachments;
        const shouldRescueSharedAttachmentsPrior = settings.shouldRescueSharedAttachments;

        /*
         * Best-effort cleanup, so it must tolerate an entry that is already gone: the rescue removes
         * emptied folders on its own queue, and trashing one a second time throws `ENOENT` from the
         * rename into `.trash` and fails a phase that already passed.
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

        async function ensureFolder(path: string): Promise<void> {
          let currentPath = '';
          for (const part of path.split('/')) {
            currentPath = currentPath ? `${currentPath}/${part}` : part;
            if (!app.vault.getAbstractFileByPath(currentPath)) {
              await app.vault.createFolder(currentPath);
            }
          }
        }

        async function runPhase(params: PhaseParams): Promise<PhaseResult> {
          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const imageName = `ar-img-${stamp}.png`;
          // Note A lives inside its own folder only when that whole folder is what gets deleted; the
          // Attachment folder pattern is note-relative, so the image goes down with it either way.
          const containerFolderPath = `ar-folder-${stamp}`;
          const noteAFolderPath = params.isFolderDeleted ? `${containerFolderPath}/` : '';
          const noteAPath = `${noteAFolderPath}ar-note-a-${stamp}.md`;
          const attachmentFolderPath = `${noteAFolderPath}assets/ar-note-a-${stamp}`;
          const imagePath = `${attachmentFolderPath}/${imageName}`;
          const noteBPath = `ar-note-b-${stamp}.md`;
          const noteCPath = `ar-note-c-${stamp}.md`;
          const expectedPath = `assets/ar-note-b-${stamp}/${imageName}`;
          const expectedNoteCount = params.shouldAddTyingNote ? 3 : 2;

          /*
         * The ELEMENTS are collected, not their text: Obsidian appends a `.notice` and fills its
         * content afterwards, so reading `textContent` inside the observer callback can capture the
         * notice while it is still empty. Reading it at the end sees the finished message.
           */
          const noticeEls: HTMLElement[] = [];
          const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
              for (const node of mutation.addedNodes) {
                if (!node.instanceOf(HTMLElement)) {
                  continue;
                }
                /*
                 * The notice is not always the added node itself: the first one of a session arrives
                 * Inside a freshly appended `.notice-container`, and matching only the node's own class
                 * Silently drops it. Its descendants are searched for that reason.
                 */
                if (node.classList.contains('notice')) {
                  noticeEls.push(node);
                }
                noticeEls.push(...node.querySelectorAll<HTMLElement>('.notice'));
              }
            }
          });

          function findNoticeText(): string {
            return noticeEls.map((noticeEl) => noticeEl.textContent).find((text) => text.includes(imageName)) ?? '';
          }

          try {
            settings.notePriorities = params.notePriorities;
            settings.shouldRescueSharedAttachments = params.shouldRescueSharedAttachments;

            await ensureFolder(attachmentFolderPath);
            await app.vault.createBinary(imagePath, new ArrayBuffer(4));
            await app.vault.create(noteAPath, `![[${imageName}]]\n`);
            await app.vault.create(noteBPath, `![[${imageName}]]\n`);
            if (params.shouldAddTyingNote) {
              await app.vault.create(noteCPath, `![[${imageName}]]\n`);
            }

            // Every embed must be indexed, or the deletion sees fewer referencing notes than the
            // Phase is built on and the rescue never has the ambiguity it is being tested against.
            await waitUntil({
              message: 'the embeds were not indexed',
              predicate: () => {
                const imageFile = app.vault.getFileByPath(imagePath);
                return imageFile !== null && app.metadataCache.getBacklinksForFile(imageFile).keys().length >= expectedNoteCount;
              },
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });

            observer.observe(document.body, { childList: true, subtree: true });

            await trashIfExists(params.isFolderDeleted ? containerFolderPath : noteAPath);

            if (params.shouldRescueSharedAttachments && !params.shouldAddTyingNote) {
              await waitUntil({
                message: `the attachment was not rescued to ${expectedPath}`,
                predicate: () => app.vault.getAbstractFileByPath(expectedPath) !== null,
                timeoutInMilliseconds: waitTimeoutInMilliseconds
              });

              /*
               * The notice announcing the move is shown around the move, not strictly before the moved
               * File is observable, so sampling it the moment the file appears is a race. Waiting for
               * It keeps the assertion intact — a rescue that never announces itself still fails here.
               */
              await waitUntil({
                message: 'the rescue was not announced by a notice',
                predicate: () => findNoticeText() !== '',
                timeoutInMilliseconds: waitTimeoutInMilliseconds
              });
            } else {
              // Nothing is expected to move, so there is no condition to wait on — only a fixed
              // Settle window long enough for the delete handling to have finished not moving it.
              await waitUntil({
                message: 'the deleted note was still present',
                predicate: () => app.vault.getAbstractFileByPath(noteAPath) === null,
                timeoutInMilliseconds: waitTimeoutInMilliseconds
              });
              await sleep(settleTimeoutInMilliseconds);
            }

            const attachmentPath = app.vault.getFiles()
              .map((file) => file.path)
              .find((path) => path.endsWith(imageName)) ?? '';

            // Obsidian rewrites the surviving embed to its shortest unambiguous form, so the
            // Destination never shows up in the markdown. The resolved link is where it is visible.
            let isResolvedFromSurvivingNote = false;
            if (attachmentPath) {
              try {
                await waitUntil({
                  message: `the surviving note did not resolve ${attachmentPath}`,
                  predicate: () => Object.keys(app.metadataCache.resolvedLinks[noteBPath] ?? {}).includes(attachmentPath),
                  timeoutInMilliseconds: waitTimeoutInMilliseconds
                });
                isResolvedFromSurvivingNote = true;
              } catch {
                isResolvedFromSurvivingNote = false;
              }
            }

            return {
              attachmentPath,
              isResolvedFromSurvivingNote,
              noticeText: findNoticeText()
            };
          } finally {
            observer.disconnect();
            for (const path of [noteCPath, noteBPath, noteAPath, expectedPath, imagePath]) {
              await trashIfExists(path);
            }
            await trashIfExists(`assets/ar-note-b-${stamp}`);
            await trashIfExists(`assets/ar-note-c-${stamp}`);
            await trashIfExists(attachmentFolderPath);
            await trashIfExists(containerFolderPath);
          }
        }

        try {
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a JS template literal.
          settings.attachmentFolderPath = './assets/${noteFileName}';
          // The rescue rides on the delete path, which this setting is what hands to the plugin.
          settings.shouldDeleteOrphanAttachments = true;

          const deletedNote = await runPhase({
            isFolderDeleted: false,
            notePriorities: [],
            shouldAddTyingNote: false,
            shouldRescueSharedAttachments: true
          });
          const deletedFolder = await runPhase({
            isFolderDeleted: true,
            notePriorities: [],
            shouldAddTyingNote: false,
            shouldRescueSharedAttachments: true
          });
          const settingOff = await runPhase({
            isFolderDeleted: false,
            notePriorities: [],
            shouldAddTyingNote: false,
            shouldRescueSharedAttachments: false
          });
          const tie = await runPhase({
            isFolderDeleted: false,
            notePriorities: [],
            shouldAddTyingNote: true,
            shouldRescueSharedAttachments: true
          });

          return {
            deletedFolder,
            deletedNote,
            isSettingsFound: true,
            settingOff,
            tie
          };
        } finally {
          /* eslint-disable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
          settings.attachmentFolderPath = priorFolderPath;
          settings.notePriorities = priorPriorities;
          settings.shouldDeleteOrphanAttachments = shouldDeleteOrphanAttachmentsPrior;
          settings.shouldRescueSharedAttachments = shouldRescueSharedAttachmentsPrior;
          /* eslint-enable require-atomic-updates -- Restoring values captured before the awaits; nothing else in this vault writes them. */
        }
      },
      input: {
        pluginId: PLUGIN_ID,
        settleTimeoutInMilliseconds: SETTLE_TIMEOUT_IN_MILLISECONDS,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.isSettingsFound).toBe(true);

    // Deleting the owning note: the image moves into the surviving note's folder, keeping its name,
    // Still resolves from that note, and the move is announced.
    expect(result.deletedNote.attachmentPath).toMatch(/^assets\/ar-note-b-.*\/ar-img-.*\.png$/);
    expect(result.deletedNote.isResolvedFromSurvivingNote).toBe(true);
    expect(result.deletedNote.noticeText).toContain('It was moved to');

    // Deleting the folder the owning note lives in ends the same way, even though the hook runs twice.
    expect(result.deletedFolder.attachmentPath).toMatch(/^assets\/ar-note-b-.*\/ar-img-.*\.png$/);
    expect(result.deletedFolder.isResolvedFromSurvivingNote).toBe(true);
    expect(result.deletedFolder.noticeText).toContain('It was moved to');

    // Control: with the setting off the image survives — that protection already shipped — but stays
    // In the deleted note's folder, and nothing announces a move.
    expect(result.settingOff.attachmentPath).toMatch(/^assets\/ar-note-a-.*\/ar-img-.*\.png$/);
    expect(result.settingOff.noticeText).not.toContain('It was moved to');

    // Control: two surviving notes that `notePriorities` cannot rank is an ambiguity the user has not
    // Resolved, so nothing is moved.
    expect(result.tie.attachmentPath).toMatch(/^assets\/ar-note-a-.*\/ar-img-.*\.png$/);
    expect(result.tie.noticeText).not.toContain('It was moved to');
  }, 300_000);
});
