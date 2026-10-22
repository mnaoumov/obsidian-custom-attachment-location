import { evalInObsidian } from 'obsidian-integration-testing';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * The paste patch is applied to the clipboard manager's prototype, which only a loaded markdown view can reach. The
 * plugin used to reach it at startup by force-loading the first markdown leaf, even a background tab Obsidian had
 * deferred. That load restored the tab's saved selection, and when another plugin had stored that selection against
 * an older version of the note, it threw `Selection points outside of document` from this plugin's startup.
 *
 * A layout whose only markdown tab sits in the background reproduces the deferred state, and a plugin reload runs the
 * startup path against it. The tab must still be deferred after the reload, and the patch must arrive once the tab is
 * shown.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
// Under the transport's ~30s per-closure cap; each wait is one plugin reload or one tab load in a small vault.
const WAIT_TIMEOUT_IN_MILLISECONDS = 8000;

interface DeferredLeafResult {
  readonly isApiFound: boolean;
  readonly isDeferredAfterReload: boolean;
  readonly isDeferredBeforeReload: boolean;
  readonly isPatchedAfterShow: boolean;
  readonly isPatchedBeforeShow: boolean;
  readonly loadedMarkdownLeafCount: number;
}

describe('A deferred markdown tab at startup', () => {
  it('stays unloaded through the plugin load, and the paste patch arrives once the tab is shown', async () => {
    const result = await evalInObsidian({
      async callback({ app, lib: { waitUntil }, pluginId, waitTimeoutInMilliseconds }): Promise<DeferredLeafResult> {
        interface ApiRecord {
          readonly api: unknown;
          readonly isRevoked: boolean;
        }

        interface ClipboardManagerLike {
          insertFiles: unknown;
        }

        interface MarkdownEditModeLike {
          readonly clipboardManager?: object;
        }

        interface MarkdownViewLike {
          readonly editMode?: MarkdownEditModeLike;
        }

        interface ObsidianLibWrapper {
          readonly __obsidianLib: ObsidianLibState;
        }

        interface ObsidianLibState {
          readonly pluginApiRegistry?: RegistryWrapper;
        }

        interface RegistryWrapper {
          readonly value?: RegistryValue;
        }

        interface RegistryValue {
          readonly records?: Record<string, ApiRecord[]>;
        }

        function isApiPublished(): boolean {
          const registryState = (window as Partial<ObsidianLibWrapper>).__obsidianLib;
          return registryState?.pluginApiRegistry?.value?.records?.[pluginId]?.some((candidate) => !candidate.isRevoked) ?? false;
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const notePath = `deferred-leaf-${stamp}.md`;
        const note = await app.vault.create(notePath, '# Deferred\n\nSome text.\n');
        const originalLayout = app.workspace.getLayout();

        try {
          const openLeaf = app.workspace.getLeaf('tab');
          await openLeaf.openFile(note);
          const openViewUnknown: unknown = openLeaf.view;
          const clipboardManager = (openViewUnknown as MarkdownViewLike).editMode?.clipboardManager;
          if (!clipboardManager) {
            throw new Error('The opened note has no clipboard manager.');
          }
          const clipboardManagerPrototype = Object.getPrototypeOf(clipboardManager) as ClipboardManagerLike;

          await app.plugins.disablePlugin(pluginId);
          const unpatchedInsertFiles = clipboardManagerPrototype.insertFiles;

          /*
           * The active tab is empty and the note's tab is in the background. Obsidian 1.14.4 defers a view only when
           * its saved state carries an icon and a title, as a saved workspace does, and its container is hidden.
           */
          await app.workspace.changeLayout({
            ...originalLayout,
            active: `empty-${stamp}`,
            main: {
              children: [{
                children: [
                  { id: `empty-${stamp}`, state: { state: {}, type: 'empty' }, type: 'leaf' },
                  {
                    id: `note-${stamp}`,
                    state: { icon: 'lucide-file', state: { file: notePath, mode: 'source' }, title: 'Deferred', type: 'markdown' },
                    type: 'leaf'
                  }
                ],
                currentTab: 0,
                id: `tabs-${stamp}`,
                type: 'tabs'
              }],
              direction: 'vertical',
              id: `main-${stamp}`,
              type: 'split'
            }
          });

          const noteLeaf = app.workspace.getLeavesOfType('markdown').find((leaf) => leaf.getViewState().state?.['file'] === notePath);
          if (!noteLeaf) {
            throw new Error('The changed layout has no tab for the note.');
          }
          const isDeferredBeforeReload = noteLeaf.isDeferred;
          const loadedMarkdownLeafCount = app.workspace.getLeavesOfType('markdown').filter((leaf) => !leaf.isDeferred).length;

          await app.plugins.enablePlugin(pluginId);
          let isApiFound = true;
          try {
            await waitUntil({
              message: 'the plugin API was not published again after the reload',
              predicate: isApiPublished,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
          } catch {
            isApiFound = false;
          }
          // The layout-ready handler runs after the API is published, so give it time to settle.
          await sleep(1000);

          const isDeferredAfterReload = noteLeaf.isDeferred;
          const isPatchedBeforeShow = clipboardManagerPrototype.insertFiles !== unpatchedInsertFiles;

          app.workspace.setActiveLeaf(noteLeaf, { focus: true });
          await app.workspace.revealLeaf(noteLeaf);
          let isPatchedAfterShow = true;
          try {
            await waitUntil({
              message: 'the paste patch never arrived after the tab was shown',
              predicate: () => clipboardManagerPrototype.insertFiles !== unpatchedInsertFiles,
              timeoutInMilliseconds: waitTimeoutInMilliseconds
            });
          } catch {
            isPatchedAfterShow = false;
          }

          return {
            isApiFound,
            isDeferredAfterReload,
            isDeferredBeforeReload,
            isPatchedAfterShow,
            isPatchedBeforeShow,
            loadedMarkdownLeafCount
          };
        } finally {
          // Every later suite shares this instance, so the layout and a live plugin are restored.
          await app.workspace.changeLayout(originalLayout);
          if (!app.plugins.enabledPlugins.has(pluginId)) {
            await app.plugins.enablePlugin(pluginId);
          }
          await app.fileManager.trashFile(note);
        }
      },
      input: {
        pluginId: PLUGIN_ID,
        waitTimeoutInMilliseconds: WAIT_TIMEOUT_IN_MILLISECONDS
      }
    });

    // The setup really produced the deferred state, with no other markdown view to patch through.
    expect(result.isDeferredBeforeReload).toBe(true);
    expect(result.loadedMarkdownLeafCount).toBe(0);
    expect(result.isApiFound).toBe(true);

    expect(result.isDeferredAfterReload).toBe(true);
    expect(result.isPatchedBeforeShow).toBe(false);
    expect(result.isPatchedAfterShow).toBe(true);
  });
});
