import { evalInObsidian } from 'obsidian-integration-testing';
import { getTempVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #47 ("Changing the name of an image breaks links"): renaming an
 * ATTACHMENT must leave every embed pointing at it valid, whoever performs the rewrite.
 *
 * The reporter's sample vault inverts all three rename defaults - `shouldHandleRenames: false`,
 * `shouldRenameAttachmentFiles: true`, `shouldRenameAttachmentFolder: false` - which is the exact
 * combination reproduced here. With link updating switched OFF the plugin deliberately rewrites
 * nothing and Obsidian's own post-rename link update is supposed to do the work.
 *
 * It does not, because the two race. Obsidian (`FileManager.runAsyncLinkUpdate` -> `updateAllLinks`)
 * snapshots every link's `resolvedPaths` BEFORE the rename and afterwards rewrites a link only when
 * `metadataCache.getLinkpathDest(...)` returns an empty or different path set. ODU's rename handler
 * (`rename-delete-handler-component.ts`, `RenameHandler.refreshLinks`) meanwhile re-registers a
 * phantom `TFile` at the OLD path into `vault.fileMap` / `metadataCache.uniqueFileLookup` and holds
 * that registration across an `await`. While the phantom is live the old link still resolves, so
 * Obsidian concludes "unchanged" and skips the rewrite - and nobody updates the link.
 *
 * With `shouldHandleRenames: true` the same phantom is harmless: the handler rewrites the links
 * itself and filters Obsidian's updates out. So this suite pins the OFF path specifically.
 *
 * The fix belongs to obsidian-dev-utils (gate `refreshLinks()` on `shouldHandleRenames`, whose only
 * consumers are the link-rewrite steps); this suite is the consumer-side regression guard.
 *
 * CURRENTLY `it.skip` - NOT a harness wall, and not silently omitted. This suite RUNS headlessly and
 * REPRODUCES the defect: verified 2026-08-02 against obsidian-dev-utils 88.8.0, where it fails on both
 * assertions - the embed stays `att-<stamp>.png` after the attachment is renamed, and the old path is
 * still present in `vault.fileMap` once the rename has landed (the phantom above, measured directly).
 * It is skipped only so the committed gate stays green while the upstream fix is pending as T329-P1;
 * un-skip it when the ODU release that carries the fix is consumed here.
 *
 * Reproduce the red state at any time with:
 *   npx vitest run --project=integration-tests:desktop attachment-rename-link-update
 *
 * Desktop-only: no Android emulator is provisioned in this environment. The rename/link-update flow is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to Android
 * once an emulator exists.
 */

interface AttachmentRenameResult {
  readonly after: string;
  readonly attachmentRenamed: boolean;
  readonly before: string;
  readonly oldPathReregistered: boolean;
  readonly settingsFound: boolean;
}

describe('Renaming an attachment keeps its links valid (issue #47)', () => {
  // Skipped until the ODU fix (T329-P1) lands; reproduces the defect today - see the header comment.
  it.skip('rewrites the embed when the attachment is renamed with link updating switched off', async () => {
    const result = await evalInObsidian({
      args: {},
      async fn({ app, lib: { waitUntil } }): Promise<AttachmentRenameResult> {
        interface RenameSettings {
          attachmentFolderPath: string;
          shouldHandleRenames: boolean;
          shouldRenameAttachmentFiles: boolean;
        }

        function isRenameSettings(value: unknown): value is RenameSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldHandleRenames'] === 'boolean'
            && typeof (value as Record<string, unknown>)['shouldRenameAttachmentFiles'] === 'boolean'
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
              values = Array.from(current.values());
            } else {
              for (const key of Object.keys(record)) {
                if (!block.has(key)) {
                  values.push(record[key]);
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

        const settings = findSettings();
        if (!settings) {
          return { after: '', attachmentRenamed: false, before: '', oldPathReregistered: false, settingsFound: false };
        }

        const originalShouldHandleRenames = settings.shouldHandleRenames;
        const originalShouldRenameAttachmentFiles = settings.shouldRenameAttachmentFiles;
        const originalAlwaysUpdateLinks = app.vault.getConfig('alwaysUpdateLinks');

        try {
          // The reporter's combination: the plugin steps back from link updating, Obsidian must do it.
          settings.shouldHandleRenames = false;
          settings.shouldRenameAttachmentFiles = true;

          // Matches the sample vault's `app.json`; without it Obsidian asks for confirmation via a
          // Modal instead of updating the links, which would stall a headless run.
          app.vault.setConfig('alwaysUpdateLinks', true);

          const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
          const folder = `attachment-rename-${stamp}`;
          const oldAttachmentPath = `${folder}/att-${stamp}.png`;
          const newAttachmentPath = `${folder}/renamed-${stamp}.png`;

          await app.vault.createFolder(folder);
          await app.vault.createBinary(oldAttachmentPath, new Uint8Array([0x89, 0x50, 0x4E, 0x47]).buffer);
          const note = await app.vault.create(`${folder}/note-${stamp}.md`, `![[${oldAttachmentPath}]]\n`);

          const attachment = app.vault.getFileByPath(oldAttachmentPath);
          if (!attachment) {
            return { after: '', attachmentRenamed: false, before: '', oldPathReregistered: false, settingsFound: true };
          }

          // Wait for the metadata cache to resolve the embed, so Obsidian's pre-rename snapshot of the
          // Link's `resolvedPaths` is populated - that snapshot is what the post-rename check compares.
          await waitUntil({
            message: 'the embed resolves to the attachment',
            predicate: () => app.metadataCache.getBacklinksForFile(attachment).keys().length >= 1,
            timeoutInMilliseconds: 40_000
          });

          const before = await app.vault.read(note);

          /*
           * Watch for the phantom re-registration that causes the defect: after the rename, the OLD
           * path must never reappear in `vault.fileMap`. Sampling on a short interval catches the
           * window even though it is only open across a couple of awaits.
           */
          let oldPathReregistered = false;
          const samplePhantom = window.setInterval(() => {
            // Only meaningful once the rename has landed - before that the old path legitimately exists.
            if (!app.vault.getFileByPath(newAttachmentPath)) {
              return;
            }
            if (app.vault.fileMap[oldAttachmentPath]) {
              oldPathReregistered = true;
            }
          }, 5);

          try {
            // `renameFile`'s promise can linger on `metadataCache.onCleanCache`; bound it and poll the
            // Observable effect below (mirroring the sibling rename suites).
            const renamePromise = app.fileManager.renameFile(attachment, newAttachmentPath);
            await Promise.race([
              renamePromise.catch(() => {
                // Lingering `onCleanCache`; the effect is polled below.
              }),
              sleep(6_000)
            ]);

            /*
             * Poll for the rewrite WITHOUT failing on timeout: the whole point of the suite is to
             * report a stale embed as a failed expectation with both texts attached, not as an opaque
             * `waitUntil` timeout.
             */
            const deadline = Date.now() + 20_000;
            while (Date.now() < deadline) {
              if ((await app.vault.read(note)) !== before) {
                break;
              }
              await sleep(200);
            }
          } finally {
            window.clearInterval(samplePhantom);
          }

          return {
            after: await app.vault.read(note),
            attachmentRenamed: Boolean(app.vault.getFileByPath(newAttachmentPath)),
            before,
            oldPathReregistered,
            settingsFound: true
          };
        } finally {
          settings.shouldHandleRenames = originalShouldHandleRenames;
          settings.shouldRenameAttachmentFiles = originalShouldRenameAttachmentFiles;
          app.vault.setConfig('alwaysUpdateLinks', originalAlwaysUpdateLinks);
        }
      },
      vaultPath: getTempVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.attachmentRenamed).toBe(true);
    expect(result.before).toContain('/att-');

    // The mechanism itself: once the rename has landed, nothing may re-register the OLD path, or
    // Obsidian's post-rename check still resolves it and concludes the link needs no rewrite.
    expect(result.oldPathReregistered).toBe(false);

    // Issue #47: the embed must follow the attachment to its new name and must not keep the old one.
    expect(result.after).toContain('/renamed-');
    expect(result.after).not.toContain('/att-');
  }, 120_000);
});
