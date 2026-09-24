import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for issue #59's fourth ask: the name cleaning Advanced Note Composer does
 * -- exactly one space between words, no leading or trailing spaces, and title case that leaves an
 * already-capitalized word alone -- available on a generated attachment name.
 *
 * Driven through `getAvailablePathForAttachments`, which is the real path every attachment save
 * resolves through, so the token evaluator, the settings and the patched Obsidian API are all
 * genuinely exercised rather than the pure formatter being unit-tested twice. The FOLDER pattern is
 * what carries the token here, because it is evaluated on every resolution --
 * `generatedAttachmentFileName` only applies when the name is actually being generated, so an
 * attachment that arrives with a name of its own would never reach it.
 *
 * The reporter's fourth rule, banning invalid characters, is deliberately NOT part of this: the plugin
 * already does it through `specialCharacters` / `specialCharactersReplacement`, and a second,
 * differently-configured idea of a valid character would only drift from the first.
 */

const PLUGIN_ID = 'obsidian-custom-attachment-location';
const RAGGED_BASE_NAME = '  my   REPORT about  api  ';

interface ProbeResult {
  readonly cleanedPath: string;
  readonly settingsFound: boolean;
  readonly untouchedPath: string;
}

describe('Name cleaning is available as a token format (issue #59)', () => {
  it('collapses whitespace and title-cases a generated name, sparing an acronym', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, pluginId, raggedBaseName }): Promise<ProbeResult> {
        interface NameSettings {
          attachmentFolderPath: string;
        }

        function isNameSettings(value: unknown): value is NameSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        const foundSettingsComponent = findSettingsComponent(app.plugins.getPlugin(pluginId), isNameSettings);
        if (!foundSettingsComponent) {
          return { cleanedPath: '', settingsFound: false, untouchedPath: '' };
        }
        // A narrowed `let`/`const` does not stay narrowed inside a function declaration below it.
        const settingsComponent = foundSettingsComponent;
        const priorFolderPath = settingsComponent.settings.attachmentFolderPath;

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const notePath = `nct-note-${stamp}.md`;

        try {
          const note = await app.vault.create(notePath, 'body\n');
          await app.workspace.getLeaf(false).openFile(note);
          await sleep(300);

          async function resolveWith(pattern: string): Promise<string> {
            await settingsComponent.editAndSave((settings) => {
              settings.attachmentFolderPath = pattern;
            });
            await sleep(200);
            return await app.vault.getAvailablePathForAttachments(raggedBaseName, 'png', note);
          }

          // The control: the same token with no cleaning, so any difference below is the new format
          // and not something else in the pipeline.
          const untouchedPath = await resolveWith('{{originalAttachmentFileName}}');
          const cleanedPath = await resolveWith('{{originalAttachmentFileName:{case:\'title\',collapseWhitespace:true}}}');

          return { cleanedPath, settingsFound: true, untouchedPath };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentFolderPath = priorFolderPath;
          });
          const note = app.vault.getAbstractFileByPath(notePath);
          if (note) {
            await app.fileManager.trashFile(note);
          }
        }
      },
      input: {
        findPluginSettingsComponent,
        pluginId: PLUGIN_ID,
        raggedBaseName: RAGGED_BASE_NAME
      },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // Without the format the ragged spacing survives into the resolved folder. Asserted as a
    // substring rather than an exact name: a trailing space is separately unusable as a folder name
    // on Windows and is dropped elsewhere, which is not what this test is about.
    expect(result.untouchedPath.split('/').slice(0, -1).join('/')).toContain('my   REPORT about  api');

    // With it: one space between words, no leading or trailing spaces, first letter of each word
    // capitalized, and `REPORT` left alone because it is already entirely upper case.
    expect(result.cleanedPath.split('/').slice(0, -1).join('/')).toBe('My REPORT About Api');

    // The file name is untouched in both, because only the folder pattern carries the token here.
    // Naming that explicitly keeps the next reader from mistaking it for a half-applied format.
    expect(result.cleanedPath.split('/').pop()).toBe(result.untouchedPath.split('/').pop());
  }, 180_000);
});
