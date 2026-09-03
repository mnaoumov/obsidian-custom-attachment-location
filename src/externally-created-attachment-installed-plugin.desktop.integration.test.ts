import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * The last thing the fabricated-stack suites cannot prove.
 *
 * `externally-created-attachment-plugin-list.desktop.integration.test.ts` compiles a writer under a
 * `//# sourceURL=plugin:<id>` trailer, which is what Obsidian's `Plugins.loadPlugin` does — but it is
 * still THIS repo doing the compiling. What remains unproven there is that a plugin Obsidian itself
 * installed, enabled and evaluated reaches the attribution the same way, with its frame still on the
 * stack at the moment it calls `vault.createBinary`.
 *
 * So this suite installs a real plugin: a `manifest.json` and a `main.js` written into the vault's
 * config folder, `loadManifests()` + `enablePlugin()` to have Obsidian compile and run it, and the write
 * issued from inside that plugin's own code. Nothing here reproduces Obsidian's mechanism — Obsidian
 * performs it.
 *
 * A purpose-built plugin rather than a third-party one (Media Extended, the plugin issue #59 was reported
 * against): the claim under test is about ANY plugin's write, no network fetch belongs in a test run, and
 * a real plugin's behavior would drift out from under the assertion.
 *
 * Desktop-only: no Android emulator is available in this environment.
 */

/**
 * The window the installed plugin parks its writer on, so the test can call the plugin's own code.
 */
interface AttachmentWriterWindow extends Window {
  writeAttachmentAsInstalledPlugin__?(path: string): Promise<unknown>;
}

interface InstalledPluginResult {
  readonly finalPaths: readonly string[];
  readonly isPluginLoaded: boolean;
  readonly settingsFound: boolean;
}

interface ScopedSettings {
  attachmentFolderPath: string;
  generatedAttachmentFileName: string;
  otherPluginIdsForAttachmentRename: readonly string[];
  renameAttachmentsCreatedByOtherPluginsMode: string;
}

const INSTALLED_PLUGIN_ID = 't753-installed-writer';

describe('An attachment written by a plugin Obsidian itself loaded (issue #77)', () => {
  async function run(mode: string, listedPluginIds: string[]): Promise<InstalledPluginResult> {
    return await evalInObsidian({
      async callback({ app, listedPluginIds: listed, mode: renameMode, pluginId }): Promise<InstalledPluginResult> {
        const WRITER_GLOBAL_NAME = 'writeAttachmentAsInstalledPlugin__';

        function isScopedSettings(value: unknown): value is ScopedSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['renameAttachmentsCreatedByOtherPluginsMode'] === 'string'
            && Array.isArray((value as Record<string, unknown>)['otherPluginIdsForAttachmentRename'])
            && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        function findSettings(): null | ScopedSettings {
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
            if (isScopedSettings(record['settings'])) {
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

        const settings = findSettings();
        if (!settings) {
          return { finalPaths: [], isPluginLoaded: false, settingsFound: false };
        }

        /*
         * One Obsidian instance is shared with every other integration file, and this is the LIVE settings
         * object. Snapshot it and put it back, or the next suite in the run inherits this scoping.
         */
        const originalSettings = {
          attachmentFolderPath: settings.attachmentFolderPath,
          generatedAttachmentFileName: settings.generatedAttachmentFileName,
          otherPluginIdsForAttachmentRename: settings.otherPluginIdsForAttachmentRename,
          renameAttachmentsCreatedByOtherPluginsMode: settings.renameAttachmentsCreatedByOtherPluginsMode
        };

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const pluginFolder = `${app.vault.configDir}/plugins/${pluginId}`;
        const createdPaths: string[] = [];

        /*
         * A minimal but genuine community plugin. Obsidian compiles this text itself, under the
         * `plugin:<id>` source URL it stamps on every plugin — which is the whole point. The writer is
         * parked on `window` so the test can call it, but the function BODY is this plugin's code, so its
         * frame is what the attribution sees.
         */
        const mainJs = [
          'const obsidian = require(\'obsidian\');',
          'class InstalledWriterPlugin extends obsidian.Plugin {',
          '  onload() {',
          `    window['${WRITER_GLOBAL_NAME}'] = (path) => this.app.vault.createBinary(path, new ArrayBuffer(8));`,
          '  }',
          '  onunload() {',
          `    delete window['${WRITER_GLOBAL_NAME}'];`,
          '  }',
          '}',
          'module.exports = InstalledWriterPlugin;'
        ].join('\n');

        const manifestJson = JSON.stringify({
          author: 'Integration test',
          description: 'Writes an attachment straight through the vault, the way issue #59 describes.',
          id: pluginId,
          isDesktopOnly: false,
          minAppVersion: '0.15.0',
          name: 'T753 Installed Writer',
          version: '1.0.0'
        });

        try {
          await app.vault.adapter.mkdir(pluginFolder);
          createdPaths.push(pluginFolder);
          await app.vault.adapter.write(`${pluginFolder}/manifest.json`, manifestJson);
          await app.vault.adapter.write(`${pluginFolder}/main.js`, mainJs);

          // `enablePlugin`, not `enablePluginAndSave`: the shared vault must not remember this plugin.
          await app.plugins.loadManifests();
          await app.plugins.enablePlugin(pluginId);

          const writeAsInstalledPlugin = (window as AttachmentWriterWindow).writeAttachmentAsInstalledPlugin__;
          if (!writeAsInstalledPlugin) {
            return { finalPaths: [], isPluginLoaded: false, settingsFound: true };
          }

          settings.renameAttachmentsCreatedByOtherPluginsMode = renameMode;
          settings.otherPluginIdsForAttachmentRename = listed;
          settings.attachmentFolderPath = `./installed-${stamp}`;
          settings.generatedAttachmentFileName = `installed-renamed-${stamp}`;

          const note = await app.vault.create(`installed-note-${stamp}.md`, '');
          const leaf = app.workspace.getLeaf(false);
          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          await sleep(500);

          const foreignFolder = `installed-foreign-${stamp}`;
          await app.vault.createFolder(foreignFolder);
          await writeAsInstalledPlugin(`${foreignFolder}/installed-img-${stamp}.png`);

          const properPath = `installed-${stamp}/installed-renamed-${stamp}.png`;
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
          return { finalPaths, isPluginLoaded: true, settingsFound: true };
        } finally {
          settings.attachmentFolderPath = originalSettings.attachmentFolderPath;
          settings.generatedAttachmentFileName = originalSettings.generatedAttachmentFileName;
          settings.otherPluginIdsForAttachmentRename = originalSettings.otherPluginIdsForAttachmentRename;
          settings.renameAttachmentsCreatedByOtherPluginsMode = originalSettings.renameAttachmentsCreatedByOtherPluginsMode;

          await app.plugins.disablePlugin(pluginId);
          for (const path of createdPaths.reverse()) {
            if (await app.vault.adapter.exists(path)) {
              await app.vault.adapter.rmdir(path, true);
            }
          }
          // So the removed plugin stops appearing in `app.plugins.manifests` for every later suite.
          await app.plugins.loadManifests();
        }
      },
      // The enum's values ARE the display strings; this code runs inside Obsidian and cannot import them.
      input: { listedPluginIds, mode, pluginId: INSTALLED_PLUGIN_ID },
      vaultPath: getTemporaryVault().path
    });
  }

  it('renames it when the plugin is listed', async () => {
    const result = await run('Only listed plugins', [INSTALLED_PLUGIN_ID]);

    expect(result.settingsFound).toBe(true);
    expect(result.isPluginLoaded).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^installed-[\d-]+\/installed-renamed-[\d-]+\.png$/);
  }, 120_000);

  it('leaves it alone when the plugin is not listed', async () => {
    const result = await run('Only listed plugins', ['some-other-plugin']);

    expect(result.settingsFound).toBe(true);
    expect(result.isPluginLoaded).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^installed-foreign-[\d-]+\/installed-img-[\d-]+\.png$/);
  }, 120_000);

  it('leaves it alone when the plugin is excluded', async () => {
    const result = await run('All except listed plugins', [INSTALLED_PLUGIN_ID]);

    expect(result.settingsFound).toBe(true);
    expect(result.isPluginLoaded).toBe(true);
    expect(result.finalPaths).toHaveLength(1);
    expect(result.finalPaths[0]).toMatch(/^installed-foreign-[\d-]+\/installed-img-[\d-]+\.png$/);
  }, 120_000);
});
