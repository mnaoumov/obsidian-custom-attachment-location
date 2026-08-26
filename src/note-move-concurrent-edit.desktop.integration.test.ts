import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #60 ("The image link is not updated"): when a note is moved, every
 * embed in it must still resolve EVEN IF something else edits the note while the move is in flight.
 *
 * This is the suite that actually reproduces the reporter's defect. Its sibling
 * (`note-move-many-attachments.desktop.integration.test.ts`) moves a note with 30 attachments and
 * passes even against the broken build: with `shouldHandleRenames: true` the handler's own
 * `FileManagerRunAsyncLinkUpdatePatchComponent` filters Obsidian's markdown link updates out, so with
 * OCAL alone nothing edits the note between the snapshot and the rewrite and no offset ever drifts.
 * That matches the one field the reporter did fill in: "Bug isolation: No, only with other plugins
 * enabled".
 *
 * So this suite supplies that second plugin in the smallest deterministic way there is: from inside
 * the vault `rename` event of the first attachment move - precisely the window between
 * `RenameMap.initBacklinksMap()` snapshotting its link keys and `editLinks()` looking them up against
 * the live metadata cache - it inserts a line in the MIDDLE of the note, shifting the offsets of every
 * link below it and leaving the ones above untouched.
 *
 * The defect: obsidian-dev-utils keyed that snapshot on `toJson(link)`, the whole `Reference`
 * INCLUDING `position`. A shifted link missed its key and hit a silent `return` - no error, no retry -
 * so it kept pointing at the attachment's old path while the links above the edit were rewritten
 * correctly. Hence "some image references will change ... while others will not change".
 *
 * The middle insertion is load-bearing, not incidental: it is what distinguishes this defect from a
 * whole-file bail-out (`applyFileChanges` returning `null` when the content changed under it), which
 * would have lost ALL the links rather than a contiguous tail.
 *
 * Measured against obsidian-dev-utils 96.0.2 (2026-08-25): 15 of 30 embeds stale, and exactly the tail
 * `img-015` ... `img-029` after the insertion point. With the fix (`getLinkIdentityKey`, keying on the
 * link's TEXT and deliberately not its position): 0 stale.
 *
 * Desktop-only: no Android emulator is provisioned in this environment. The rename/link-update flow is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to Android
 * once an emulator exists.
 */

interface ConcurrentEditResult {
  readonly after: string;
  readonly attachmentCount: number;
  readonly editApplied: boolean;
  readonly movedAttachmentCount: number;
  readonly noteRenamed: boolean;
  readonly settingsFound: boolean;
  readonly staleLinks: readonly string[];
  readonly totalLinks: number;
}

describe('A concurrent edit during a note move keeps every attachment link valid (issue #60)', () => {
  it('rewrites every embed when the note is edited inside the rename window', async () => {
    const ATTACHMENT_COUNT = 30;
    const result = await evalInObsidian({
      async callback({ app, attachmentCount, lib: { waitUntil } }): Promise<ConcurrentEditResult> {
        interface RenameSettings {
          attachmentFolderPath: string;
          shouldHandleRenames: boolean;
          shouldRenameAttachmentFolder: boolean;
        }

        function isRenameSettings(value: unknown): value is RenameSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldHandleRenames'] === 'boolean'
            && typeof (value as Record<string, unknown>)['shouldRenameAttachmentFolder'] === 'boolean'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        function findSettings(): null | RenameSettings {
          const block = new Set(['app', 'containerEl', 'dom', 'metadataCache', 'plugins', 'vault', 'workspace']);
          const seen = new Set<unknown>();
          const queue: unknown[] = [app.plugins.getPlugin('obsidian-custom-attachment-location')];
          let budget = 12_000;
          while (queue.length > 0 && budget-- > 0) {
            const current = queue.shift();
            if (current === null || (typeof current !== 'object' && typeof current !== 'function') || seen.has(current)) {
              continue;
            }
            seen.add(current);
            const record = current as Record<string, unknown>;
            if (isRenameSettings(record['settings'])) {
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

        const emptyResult: ConcurrentEditResult = {
          after: '',
          attachmentCount,
          editApplied: false,
          movedAttachmentCount: 0,
          noteRenamed: false,
          settingsFound: false,
          staleLinks: [],
          totalLinks: 0
        };

        const settings = findSettings();
        if (!settings) {
          return emptyResult;
        }

        const isOriginalShouldHandleRenames = settings.shouldHandleRenames;
        const isOriginalShouldRenameAttachmentFolder = settings.shouldRenameAttachmentFolder;
        const originalAttachmentFolderPath = settings.attachmentFolderPath;
        const originalAlwaysUpdateLinks = app.vault.getConfig('alwaysUpdateLinks');
        const originalNewLinkFormat = app.vault.getConfig('newLinkFormat');

        let eventRef: null | ReturnType<typeof app.vault.on> = null;

        try {
          settings.shouldHandleRenames = true;
          settings.shouldRenameAttachmentFolder = true;
          // eslint-disable-next-line no-template-curly-in-string -- A plugin token evaluated by the plugin, not a JS template literal.
          settings.attachmentFolderPath = './assets/${noteFileName}';
          app.vault.setConfig('alwaysUpdateLinks', true);
          app.vault.setConfig('newLinkFormat', 'absolute');

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const folder = `note-move-edit-${stamp}`;
          const oldNoteName = `n-${stamp}`;
          const newNoteName = `renamed-note-with-a-longer-name-${stamp}`;
          const oldNotePath = `${folder}/${oldNoteName}.md`;
          const newNotePath = `${folder}/${newNoteName}.md`;
          const oldAttachmentFolder = `${folder}/assets/${oldNoteName}`;
          const newAttachmentFolder = `${folder}/assets/${newNoteName}`;

          await app.vault.createFolder(folder);
          await app.vault.createFolder(`${folder}/assets`);
          await app.vault.createFolder(oldAttachmentFolder);

          const lines: string[] = [];
          for (let index = 0; index < attachmentCount; index++) {
            const attachmentPath = `${oldAttachmentFolder}/img-${index.toString().padStart(3, '0')}.png`;
            await app.vault.createBinary(attachmentPath, new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer);
            lines.push(`Image ${index.toString()}: ![[${attachmentPath}]]`);
          }

          const note = await app.vault.create(oldNotePath, `${lines.join('\n\n')}\n`);

          await waitUntil({
            message: 'every embed in the note resolves to its attachment',
            predicate: () => (app.metadataCache.getCache(note.path)?.embeds ?? []).length >= attachmentCount,
            timeoutInMilliseconds: 60_000
          });

          /*
           * The emulated second plugin. It fires on the FIRST attachment rename - which happens after
           * the handler has snapshotted its link keys and before it rewrites - and prepends a line,
           * shifting every link's offsets. A real co-installed link-rewriting plugin perturbs the same
           * window; this is the minimal deterministic stand-in for it.
           */
          let isEditApplied = false;
          eventRef = app.vault.on('rename', (file) => {
            if (isEditApplied || !file.path.startsWith(`${newAttachmentFolder}/`)) {
              return;
            }
            isEditApplied = true;
            const noteFile = app.vault.getFileByPath(newNotePath) ?? app.vault.getFileByPath(oldNotePath);
            if (!noteFile) {
              return;
            }
            /*
             * Insert in the MIDDLE, not at the top. This is the discriminator between the two
             * candidate mechanisms: if the fragile `toJson(link)` key is at fault, the links BEFORE
             * the insertion keep their offsets and are rewritten while only the tail after it is
             * silently skipped (the reporter's partial signature); if instead the whole rewrite bails
             * out (`applyFileChanges` returning `null` when the content changed under it), all of them
             * stay stale regardless of where the edit landed.
             */
            app.vault.process(noteFile, (content) => {
              const blocks = content.split('\n\n');
              const insertAt = Math.floor(blocks.length / 2);
              return [...blocks.slice(0, insertAt), 'A line inserted mid-rename to shift the offsets after it.', ...blocks.slice(insertAt)].join('\n\n');
            }).catch(() => {
              /*
               * The vault `rename` callback is synchronous, so this edit is fire-and-forget. A failure here is not
               * swallowed silently: `editApplied` is asserted below, and the whole suite is meaningless without it.
               */
            });
          });

          const renamePromise = app.fileManager.renameFile(note, newNotePath);
          await Promise.race([
            renamePromise.catch(() => {
              // Lingering `onCleanCache`; the effect is polled below.
            }),
            sleep(10_000)
          ]);

          await waitUntil({
            message: 'every attachment has moved into the renamed note\'s folder',
            predicate: () => app.vault.getFiles().filter((file) => file.path.startsWith(`${newAttachmentFolder}/`)).length >= attachmentCount,
            timeoutInMilliseconds: 90_000
          });

          let after = await app.vault.read(app.vault.getFileByPath(newNotePath) ?? note);
          let stableSince = Date.now();
          const settleDeadline = Date.now() + 60_000;
          while (Date.now() < settleDeadline) {
            await sleep(250);
            const current = await app.vault.read(app.vault.getFileByPath(newNotePath) ?? note);
            if (current === after) {
              if (Date.now() - stableSince >= 3000) {
                break;
              }
            } else {
              after = current;
              stableSince = Date.now();
            }
          }

          const linkPaths = [...after.matchAll(/!\[\[(?<linkPath>[^\]|]+)/g)]
            .map((match) => match.groups?.['linkPath']?.trim() ?? '')
            .filter((linkPath) => linkPath !== '');

          return {
            after,
            attachmentCount,
            editApplied: isEditApplied,
            movedAttachmentCount: app.vault.getFiles().filter((file) => file.path.startsWith(`${newAttachmentFolder}/`)).length,
            noteRenamed: Boolean(app.vault.getFileByPath(newNotePath)),
            settingsFound: true,
            staleLinks: linkPaths.filter((linkPath) => !app.metadataCache.getFirstLinkpathDest(linkPath, newNotePath)),
            totalLinks: linkPaths.length
          };
        } finally {
          if (eventRef) {
            app.vault.offref(eventRef);
          }
          settings.shouldHandleRenames = isOriginalShouldHandleRenames;
          settings.shouldRenameAttachmentFolder = isOriginalShouldRenameAttachmentFolder;
          settings.attachmentFolderPath = originalAttachmentFolderPath;
          app.vault.setConfig('alwaysUpdateLinks', originalAlwaysUpdateLinks);
          app.vault.setConfig('newLinkFormat', originalNewLinkFormat);
        }
      },
      input: { attachmentCount: ATTACHMENT_COUNT },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.noteRenamed).toBe(true);

    /*
     * The emulated second plugin really did edit the note inside the rename window. Without this the suite would
     * silently degrade into a duplicate of the plain scale suite and prove nothing.
     */
    expect(result.editApplied).toBe(true);

    // The scenario staged what it claims to: the note kept all its embeds and every attachment moved.
    expect(result.totalLinks).toBe(ATTACHMENT_COUNT);
    expect(result.movedAttachmentCount).toBe(ATTACHMENT_COUNT);

    /*
     * Issue #60: EVERY embed must still resolve. Asserted on the full list rather than a count so a
     * regression names the links that went stale - and their identity is the evidence for the
     * mechanism, since the broken build fails with exactly the contiguous tail after the insertion.
     */
    expect(result.staleLinks).toStrictEqual([]);
  }, 300_000);
});
