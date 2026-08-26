import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #60 ("The image link is not updated"): renaming a NOTE must leave
 * EVERY embed in it pointing at a real file, however many attachments the note has.
 *
 * The reporter's only usable observation is a scale threshold - "when there are few images in the
 * file, the image references can be modified normally. However, when there are many images in the
 * file, some image references will change ... while others will not change" - so this suite runs the
 * SAME scenario at two sizes, 3 and 30.
 *
 * IT DOES NOT REPRODUCE THE DEFECT, and that negative result is why it is worth keeping. Measured
 * against the broken obsidian-dev-utils 96.0.2 (2026-08-25): both sizes green, 0 stale embeds. The
 * reason is that with `shouldHandleRenames: true` the handler's own
 * `FileManagerRunAsyncLinkUpdatePatchComponent` discards Obsidian's native markdown link updates, so
 * with OCAL alone NOTHING edits the note between the moment the rewrite plan is snapshotted and the
 * moment it is applied - no link offset ever drifts, and the fragile lookup always hits.
 *
 * Reproducing it needs a second party editing the note inside that window, which is what the
 * reporter's "Bug isolation: No, only with other plugins enabled" was telling us all along. That is
 * `note-move-concurrent-edit.desktop.integration.test.ts`, which supplies exactly such an edit and
 * fails 15/30 without the fix. Keep the two together: this one guards the plain path (and would catch
 * a regression that breaks moves outright), its sibling guards the defect itself.
 *
 * Two vault settings are set deliberately, because with the defaults the scenario could not exhibit
 * the defect at all even in principle, and the suite would be green for a second, wrong reason:
 *   - `newLinkFormat: 'absolute'` - with the default shortest-path format the rewritten link text is
 *     just the bare filename, identical before and after the move, so no offsets ever shift.
 *   - the new note name is LONGER than the old one - the note name is embedded in every link via the
 *     default `attachmentFolderPath` of `./assets/${noteFileName}`, so a length change is what makes
 *     each rewrite shift the links after it.
 *
 * Assertions are by RESOLUTION (`metadataCache.getFirstLinkpathDest`), never by link text: Obsidian
 * rewrites using the vault's configured link format, so a correct rewrite legitimately comes back in a
 * different shape. What the reporter cares about, and all that "the image link is not updated" means,
 * is whether the link still points at a file.
 *
 * Desktop-only: no Android emulator is provisioned in this environment. The rename/link-update flow is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to Android
 * once an emulator exists.
 */

interface NoteMoveResult {
  readonly after: string;
  readonly attachmentCount: number;
  readonly movedAttachmentCount: number;
  readonly noteRenamed: boolean;
  readonly settingsFound: boolean;
  readonly staleLinks: readonly string[];
  readonly totalLinks: number;
}

describe('Moving a note keeps every attachment link valid (issue #60)', () => {
  for (const attachmentCount of [3, 30]) {
    it(`rewrites every embed when a note with ${attachmentCount.toString()} attachments is renamed`, async () => {
      const result = await evalInObsidian({
        async callback({ app, attachmentCount: count, lib: { waitUntil } }): Promise<NoteMoveResult> {
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

          // The plugin does not expose its settings publicly, so locate the live settings object by
          // Walking the plugin's component tree (same approach as the other OCAL integration tests).
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

          const emptyResult: NoteMoveResult = {
            after: '',
            attachmentCount: count,
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

          try {
            // The plugin defaults, stated explicitly so the scenario does not silently drift with them.
            settings.shouldHandleRenames = true;
            settings.shouldRenameAttachmentFolder = true;
            // eslint-disable-next-line no-template-curly-in-string -- A plugin token evaluated by the plugin, not a JS template literal.
            settings.attachmentFolderPath = './assets/${noteFileName}';

            /*
             * Without this Obsidian asks for confirmation via a Modal instead of updating the links, which would stall
             * a headless run.
             */
            app.vault.setConfig('alwaysUpdateLinks', true);

            /*
             * See the file header: the default shortest-path format would keep every rewritten link textually
             * identical, so no offsets would ever shift and the defect could not appear.
             */
            app.vault.setConfig('newLinkFormat', 'absolute');

            const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
            const folder = `note-move-${stamp}`;
            const oldNoteName = `n-${stamp}`;
            /*
             * Deliberately LONGER than the old name, so every link's text grows and the links after the first rewrite
             * shift - see the file header.
             */
            const newNoteName = `renamed-note-with-a-longer-name-${stamp}`;
            const oldNotePath = `${folder}/${oldNoteName}.md`;
            const newNotePath = `${folder}/${newNoteName}.md`;
            const oldAttachmentFolder = `${folder}/assets/${oldNoteName}`;
            const newAttachmentFolder = `${folder}/assets/${newNoteName}`;

            await app.vault.createFolder(folder);
            await app.vault.createFolder(`${folder}/assets`);
            await app.vault.createFolder(oldAttachmentFolder);

            const attachmentPaths: string[] = [];
            const lines: string[] = [];
            for (let index = 0; index < count; index++) {
              const attachmentPath = `${oldAttachmentFolder}/img-${index.toString().padStart(3, '0')}.png`;
              await app.vault.createBinary(attachmentPath, new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer);
              attachmentPaths.push(attachmentPath);
              lines.push(`Image ${index.toString()}: ![[${attachmentPath}]]`);
            }

            const note = await app.vault.create(oldNotePath, `${lines.join('\n\n')}\n`);

            /*
             * Wait for the metadata cache to resolve EVERY embed. The rename handler builds its rewrite plan from this
             * cache, so a half-resolved note would under-report the defect.
             */
            await waitUntil({
              message: 'every embed in the note resolves to its attachment',
              predicate: () => {
                const links = app.metadataCache.getCache(note.path)?.embeds ?? [];
                return links.length >= count;
              },
              timeoutInMilliseconds: 60_000
            });

            /*
             * `renameFile`'s promise can linger on `metadataCache.onCleanCache`; bound it and poll the
             * observable effect below (mirroring the sibling rename suites).
             */
            const renamePromise = app.fileManager.renameFile(note, newNotePath);
            await Promise.race([
              renamePromise.catch(() => {
                // Lingering `onCleanCache`; the effect is polled below.
              }),
              sleep(10_000)
            ]);

            /*
             * The attachments move first; wait for that pass to finish before judging the links, so a slow move is not
             * misreported as a link-update failure.
             */
            await waitUntil({
              message: 'every attachment has moved into the renamed note\'s folder',
              predicate: () => {
                const moved = app.vault.getFiles().filter((file) => file.path.startsWith(`${newAttachmentFolder}/`));
                return moved.length >= count;
              },
              timeoutInMilliseconds: 90_000
            });

            /*
             * The link rewrite runs on an internal queue after the moves. Poll until the note's
             * content stops changing, rather than asserting on the first read - a stale link must be a
             * genuinely settled result, not a race with the rewrite still in flight.
             */
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

            /*
             * The reporter's actual complaint: does the link still point at a file? Resolve each embed
             * rather than matching its text - Obsidian rewrites in the vault's configured link format,
             * so a correct rewrite can legitimately change shape.
             */
            const linkPaths = [...after.matchAll(/!\[\[(?<linkPath>[^\]|]+)/g)]
              .map((match) => match.groups?.['linkPath']?.trim() ?? '')
              .filter((linkPath) => linkPath !== '');

            const staleLinks = linkPaths.filter((linkPath) => !app.metadataCache.getFirstLinkpathDest(linkPath, newNotePath));

            const movedAttachmentCount = app.vault.getFiles().filter((file) => file.path.startsWith(`${newAttachmentFolder}/`)).length;

            return {
              after,
              attachmentCount: count,
              movedAttachmentCount,
              noteRenamed: Boolean(app.vault.getFileByPath(newNotePath)),
              settingsFound: true,
              staleLinks,
              totalLinks: linkPaths.length
            };
          } finally {
            settings.shouldHandleRenames = isOriginalShouldHandleRenames;
            settings.shouldRenameAttachmentFolder = isOriginalShouldRenameAttachmentFolder;
            settings.attachmentFolderPath = originalAttachmentFolderPath;
            app.vault.setConfig('alwaysUpdateLinks', originalAlwaysUpdateLinks);
            app.vault.setConfig('newLinkFormat', originalNewLinkFormat);
          }
        },
        input: { attachmentCount },
        vaultPath: getTemporaryVault().path
      });

      expect(result.settingsFound).toBe(true);
      expect(result.noteRenamed).toBe(true);

      /*
       * The scenario really staged what it claims to: the note kept all its embeds and every attachment followed it.
       * Without these, a stale-link count of 0 would prove nothing.
       */
      expect(result.totalLinks).toBe(attachmentCount);
      expect(result.movedAttachmentCount).toBe(attachmentCount);

      /*
       * Issue #60: EVERY embed must still resolve. Asserted on the full list rather than a count so a
       * partial failure names the links that went stale - which of them fail is the evidence for the
       * position-drift mechanism (the tail of the note, not a random subset).
       */
      expect(result.staleLinks).toStrictEqual([]);
    }, 300_000);
  }
});
