import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for special characters in a name the plugin KEEPS
 * (https://github.com/RainCat1998/obsidian-custom-attachment-location/issues/141).
 *
 * Under `Only pasted images` a dropped file keeps its name, so it never meets the file-name template, which is where
 * special characters are replaced. A `#` left in that name turns the embed into a heading link, and the link breaks.
 * The drop is dispatched for the reason `screenshot-file-paste.desktop.integration.test.ts` gives: a trusted drop
 * needs an OS drag from another application. It still runs Obsidian's own drop handler, `insertFiles` and
 * `saveAttachment`.
 */

interface EditorLike {
  readonly cm?: EditorViewLike;
}

interface EditorViewLike {
  readonly contentDOM: HTMLElement;
}

interface KeptNameResult {
  readonly error: string;
  readonly isLinkResolved: boolean;
  readonly noteContent: string;
  readonly savedName: string;
  readonly settingsFound: boolean;
}

interface MarkdownViewLike {
  readonly editor?: EditorLike;
}

describe('special characters in a kept attachment name', () => {
  it('replaces them in a file dropped under Only pasted images, so its link resolves', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent, lib: { waitUntil } }): Promise<KeptNameResult> {
        interface KeptNameSettings {
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          attachmentRenameMode: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          specialCharacters: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          specialCharactersReplacement: string;
        }

        function isKeptNameSettings(value: unknown): value is KeptNameSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentRenameMode'] === 'string'
            && typeof (value as Record<string, unknown>)['specialCharacters'] === 'string';
        }

        const empty = { error: '', isLinkResolved: false, noteContent: '', savedName: '' };
        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isKeptNameSettings);
        if (!settingsComponent) {
          return { ...empty, settingsFound: false };
        }

        const prior = { ...settingsComponent.settings };
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;

        try {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentRenameMode = 'Only pasted images';
            settings.attachmentFolderPath = './';
            settings.specialCharacters = String.raw`#^[]|*\<>:?/`;
            settings.specialCharactersReplacement = '-';
          });

          const note = await app.vault.create(`kept-name-note-${stamp}.md`, '');
          const leaf = app.workspace.getLeaf(true);
          await leaf.openFile(note);
          await app.workspace.revealLeaf(leaf);
          app.workspace.setActiveLeaf(leaf, { focus: true });
          await sleep(500);

          const viewUnknown: unknown = leaf.view;
          const contentDom = (viewUnknown as MarkdownViewLike).editor?.cm?.contentDOM;
          if (!contentDom) {
            return { ...empty, error: 'no editor content DOM', settingsFound: true };
          }
          contentDom.focus();

          const file = new File(['dropped'], `kept#name-${stamp}.txt`, { type: 'text/plain' });
          const dataTransfer = new DataTransfer();
          dataTransfer.items.add(file);
          const rect = contentDom.getBoundingClientRect();
          // eslint-disable-next-line obsidian-dev-toolkit/no-untrusted-input-events -- `sendInputEvent` cannot express a drag; the wait below fails unless Obsidian really saved the dropped file.
          contentDom.dispatchEvent(
            new DragEvent('drop', {
              bubbles: true,
              cancelable: true,
              clientX: rect.left + 5,
              clientY: rect.top + 5,
              dataTransfer
            })
          );

          let savedName = '';
          const SAVE_TIMEOUT_IN_MILLISECONDS = 10_000;
          await waitUntil({
            message: 'the dropped file to be saved and linked',
            predicate: async () => {
              savedName = app.vault.getFiles().find((vaultFile) => vaultFile.name.includes(`name-${stamp}`) && vaultFile.extension === 'txt')?.name ?? '';
              const content = await app.vault.read(note);
              return savedName !== '' && content.includes('[[');
            },
            timeoutInMilliseconds: SAVE_TIMEOUT_IN_MILLISECONDS
          });

          const noteContent = await app.vault.read(note);
          const linkText = /\[\[(?<Link>[^\]|]+)/.exec(noteContent)?.groups?.['Link'] ?? '';
          const isLinkResolved = app.metadataCache.getFirstLinkpathDest(linkText, note.path)?.name === savedName;
          leaf.detach();

          return { error: '', isLinkResolved, noteContent, savedName, settingsFound: true };
        } catch (error) {
          return { ...empty, error: String(error), settingsFound: true };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.attachmentRenameMode = prior.attachmentRenameMode;
            settings.attachmentFolderPath = prior.attachmentFolderPath;
            settings.specialCharacters = prior.specialCharacters;
            settings.specialCharactersReplacement = prior.specialCharactersReplacement;
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.error).toBe('');
    expect(result.savedName).toMatch(/^kept-name-[\d-]+\.txt$/);
    expect(result.isLinkResolved, result.noteContent).toBe(true);
  }, 60_000);
});
