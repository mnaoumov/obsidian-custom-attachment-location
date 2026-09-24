import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for issue #77: the rename of an attachment another plugin created can be scoped to
 * a named set of plugins, in either polarity.
 *
 * The load-bearing claim under test is the ATTRIBUTION, and it is the one thing a unit test cannot fully
 * settle: Obsidian evaluates a community plugin's `main.js` with `//# sourceURL=plugin:<id>`, so a write
 * made from that code carries the id on its call stack. This suite reproduces that evaluation exactly —
 * the same `//# sourceURL=plugin:<id>` on a function compiled inside the running Obsidian — and drives a
 * real `vault.createBinary` through it, so a real Obsidian is what confirms the mechanism rather than a
 * fixture string.
 *
 * A fabricated id is used deliberately: no third-party plugin has to be installed for the attribution to
 * be exercised, and the assertion cannot silently pass because some real plugin happened to be present.
 *
 * Desktop-only: no Android emulator is available in this environment. The behavior is cross-platform, so
 * renaming this file to `*.cross-platform.integration.test.ts` lifts it to Android once one exists.
 */

interface EditableViewLike {
  readonly editor?: EditorLike;
}

interface EditorLike {
  replaceSelection: (text: string) => void;
}

interface PluginListResult {
  readonly finalPaths: readonly string[];
  readonly settingsFound: boolean;
}

interface ScopedSettings {
  attachmentFolderPath: string;
  generatedAttachmentFileName: string;
  otherPluginIdsForAttachmentRename: string[];
  renameAttachmentsCreatedByOtherPluginsMode: string;
}

const FAKE_PLUGIN_ID = 'fake-attribution-plugin';

describe('Scoping the foreign-attachment rename to named plugins (issue #77)', () => {
  async function run(mode: string, listedPluginIds: string[]): Promise<PluginListResult> {
    return await evalInObsidian({
      async callback({ app, fakePluginId, findPluginSettingsComponent: findSettingsComponent, listedPluginIds: listed, mode: renameMode }): Promise<PluginListResult> {
        function isScopedSettings(value: unknown): value is ScopedSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['renameAttachmentsCreatedByOtherPluginsMode'] === 'string'
            && Array.isArray((value as Record<string, unknown>)['otherPluginIdsForAttachmentRename'])
            && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isScopedSettings);
        if (!settingsComponent) {
          return { finalPaths: [], settingsFound: false };
        }

        /*
         * One Obsidian instance is shared with every other integration file, and these are the LIVE, saved
         * settings. Snapshot them and put them back, or the next suite in the run inherits this scoping.
         */
        const originalSettings = {
          attachmentFolderPath: settingsComponent.settings.attachmentFolderPath,
          generatedAttachmentFileName: settingsComponent.settings.generatedAttachmentFileName,
          otherPluginIdsForAttachmentRename: settingsComponent.settings.otherPluginIdsForAttachmentRename,
          renameAttachmentsCreatedByOtherPluginsMode: settingsComponent.settings.renameAttachmentsCreatedByOtherPluginsMode
        };

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        await settingsComponent.editAndSave((settings) => {
          settings.renameAttachmentsCreatedByOtherPluginsMode = renameMode;
          settings.otherPluginIdsForAttachmentRename = listed;
          settings.attachmentFolderPath = `./scoped-${stamp}`;
          settings.generatedAttachmentFileName = `scoped-renamed-${stamp}`;
        });

        try {
          const note = await app.vault.create(`scoped-note-${stamp}.md`, '');
          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          await sleep(500);

          const foreignFolder = `scoped-foreign-${stamp}`;
          await app.vault.createFolder(foreignFolder);
          const foreignPath = `${foreignFolder}/scoped-img-${stamp}.png`;

          /*
           * The whole point of the suite. Compiling a function body with a `//# sourceURL=plugin:<id>`
           * trailer is what Obsidian's `Plugins.loadPlugin` does to every community plugin's `main.js`, so
           * the frames this function produces are indistinguishable from that plugin's own — which is what
           * the attribution reads. Calling `vault.createBinary` from anywhere else carries no plugin id.
           */
          const writeAsPlugin = new Function(
            'vault',
            'path',
            `return vault.createBinary(path, new ArrayBuffer(8));\n//# sourceURL=plugin:${fakePluginId}\n`
          ) as (vault: typeof app.vault, path: string) => Promise<unknown>;
          await writeAsPlugin(app.vault, foreignPath);
          /*
           * ...and link it from the note, as a plugin inserting an attachment does. A file no note links to is that
           * plugin's own data and is never moved (issue #88), so without the embed there is nothing to test here.
           */
          (leaf.view as EditableViewLike).editor?.replaceSelection(`![[scoped-img-${stamp}.png]]`);

          const properPath = `scoped-${stamp}/scoped-renamed-${stamp}.png`;
          const deadline = Date.now() + 15_000;
          while (Date.now() < deadline) {
            if (app.vault.getFileByPath(properPath)) {
              break;
            }
            await sleep(300);
          }

          // A settled read: when the plugin is out of scope, nothing should ever have moved.
          await sleep(1000);
          const finalPaths = app.vault.getFiles()
            .map((file) => file.path)
            .filter((path) => path.includes(stamp) && path.endsWith('.png'));

          leaf.detach();

          return { finalPaths, settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = originalSettings.attachmentFolderPath;
            settings.generatedAttachmentFileName = originalSettings.generatedAttachmentFileName;
            settings.otherPluginIdsForAttachmentRename = originalSettings.otherPluginIdsForAttachmentRename;
            settings.renameAttachmentsCreatedByOtherPluginsMode = originalSettings.renameAttachmentsCreatedByOtherPluginsMode;
          });
        }
      },
      // The enum's values ARE the display strings; this code runs inside Obsidian and cannot import them.
      input: { fakePluginId: FAKE_PLUGIN_ID, findPluginSettingsComponent, listedPluginIds, mode },
      vaultPath: getTemporaryVault().path
    });
  }

  it('renames an attachment written by a listed plugin', async () => {
    const result = await run('Only listed plugins', [FAKE_PLUGIN_ID]);

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^scoped-[\d-]+\/scoped-renamed-[\d-]+\.png$/);
  }, 120_000);

  it('leaves an attachment written by an unlisted plugin exactly where it was written', async () => {
    const result = await run('Only listed plugins', ['some-other-plugin']);

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^scoped-foreign-[\d-]+\/scoped-img-[\d-]+\.png$/);
  }, 120_000);

  it('leaves an attachment written by an excluded plugin exactly where it was written', async () => {
    const result = await run('All except listed plugins', [FAKE_PLUGIN_ID]);

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^scoped-foreign-[\d-]+\/scoped-img-[\d-]+\.png$/);
  }, 120_000);

  it('renames an attachment written by a plugin that is not excluded', async () => {
    const result = await run('All except listed plugins', ['some-other-plugin']);

    expect(result.settingsFound).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^scoped-[\d-]+\/scoped-renamed-[\d-]+\.png$/);
  }, 120_000);
});
