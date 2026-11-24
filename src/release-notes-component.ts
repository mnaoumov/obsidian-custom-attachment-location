import type { ReleaseNotes } from '@mnaoumov/obsidian-lib/components/release-notes-component';
import type { App } from 'obsidian';

import { ReleaseNotesComponent } from '@mnaoumov/obsidian-lib/components/release-notes-component';
import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { alert } from '@mnaoumov/obsidian-lib/modals/alert';
import { noop } from '@mnaoumov/typescript-lib/function';
import { compare } from 'semver';

import type { PluginSettingsComponent } from './settings/plugin-settings-component.ts';

import {
  CUSTOM_TOKENS_DOCUMENTATION_URL,
  MARKDOWN_URL_FORMAT_DOCUMENTATION_URL,
  TOKEN_REFERENCE_DOCUMENTATION_URL
} from './documentation-links.ts';
import {
  codeNode,
  linkNode,
  translateFragment
} from './i18n/translate-fragment.ts';

interface CreateReleaseNotesComponentParams {
  readonly app: App;
  readonly pluginDirectory: string;
  readonly pluginName: string;
  readonly pluginSettingsComponent: PluginSettingsComponent;
  readonly pluginVersion: string;
}

interface ShowVersionMismatchWarningParams {
  readonly app: App;
  readonly pluginDirectory: string;
  readonly pluginName: string;
  readonly pluginVersion: string;
  readonly storedVersion: string;
}

/*
 * The popup itself is `@mnaoumov/obsidian-lib`'s `ReleaseNotesComponent`: it names the plugin in its title and waits for
 * `data.json` to be read before deciding what was already shown. What stays here is this plugin's storage, the
 * version-mismatch warning, and the notes themselves.
 *
 * The shown list is not stored. It is derived from `settings.version`, the plugin version last started: every
 * note up to it counts as shown. A fresh install has no stored version, and counts every note as shown, because
 * a note about a change is news only to someone who used the plugin before it.
 */
export function createReleaseNotesComponent(params: CreateReleaseNotesComponentParams): ReleaseNotesComponent {
  const { app, pluginDirectory, pluginName, pluginSettingsComponent, pluginVersion } = params;

  // The version stored before this start, captured before it is overwritten below.
  let previousVersion = '';

  return new ReleaseNotesComponent({
    app,
    getShownReleaseNoteVersions: (): readonly string[] => Object.keys(buildReleaseNotes()).filter((version) => !previousVersion || compare(version, previousVersion) <= 0),
    pluginName,
    pluginSettingsComponent,
    releaseNotesProvider: buildReleaseNotes,
    // `shouldShowReleaseNotes` has already written the plugin version, which is what records every note up to it.
    setShownReleaseNoteVersions: noop,
    /*
     * The library calls this before it reads the shown list, so the version work lives here: written anywhere
     * else, the write-back races that read and the notes are never shown.
     *
     * The write-back runs on every start, not only when there are notes, so the stored version stays the one
     * last started. A stored version NEWER than the plugin is a downgrade or a copied `data.json`: that is
     * warned about, and the stored version is left alone rather than being silently rolled back.
     */
    shouldShowReleaseNotes: async (): Promise<boolean> => {
      const storedVersion = pluginSettingsComponent.settings.version;

      if (storedVersion && compare(pluginVersion, storedVersion) < 0) {
        await showVersionMismatchWarning({ app, pluginDirectory, pluginName, pluginVersion, storedVersion });
        return false;
      }

      previousVersion = storedVersion;
      await pluginSettingsComponent.editAndSave((settings) => {
        settings.version = pluginVersion;
      });
      return true;
    }
  });
}

function buildReleaseNotes(): ReleaseNotes {
  return {
    /* eslint-disable perfectionist/sort-objects -- Need to keep versions in order. */
    '9.0.0': createFragment((f) => {
      f.append(translateFragment(($) => $.pluginSettingsManager.customToken.deprecated, {
        documentation: linkNode(CUSTOM_TOKENS_DOCUMENTATION_URL, t(($) => $.links.documentation))
      }));
      f.createEl('br');
      f.append(translateFragment(($) => $.pluginSettingsManager.legacyRenameAttachmentsToLowerCase, {
        documentation: linkNode(TOKEN_REFERENCE_DOCUMENTATION_URL, t(($) => $.links.documentation)),
        format: codeNode('lower'),
        setting: codeNode(t(($) => $.pluginSettingsTab.renameAttachmentsToLowerCase))
      }));
    }),
    '9.2.0': translateFragment(($) => $.pluginSettingsManager.markdownUrlFormat.deprecated, {
      documentation: linkNode(MARKDOWN_URL_FORMAT_DOCUMENTATION_URL, t(($) => $.links.documentation)),
      setting: codeNode(t(($) => $.pluginSettingsTab.markdownUrlFormat.name))
    }),
    '9.16.0': translateFragment(($) => $.pluginSettingsManager.specialCharacters, {
      setting: codeNode(t(($) => $.pluginSettingsTab.specialCharacters.name))
    }),
    '10.0.0': translateFragment(($) => $.releaseNotes.versions['10.0.0'], {
      documentation: linkNode(TOKEN_REFERENCE_DOCUMENTATION_URL, t(($) => $.links.documentation))
    }),
    '11.0.0': translateFragment(($) => $.releaseNotes.versions['11.0.0'], {
      documentation: linkNode(CUSTOM_TOKENS_DOCUMENTATION_URL, t(($) => $.links.documentation)),
      newMethod: codeNode('await context.getAttachmentFileContent()'),
      oldProperty: codeNode('context.attachmentFileContent')
    })
    /* eslint-enable perfectionist/sort-objects -- Need to keep versions in order. */
  };
}

async function showVersionMismatchWarning(params: ShowVersionMismatchWarningParams): Promise<void> {
  const { app, pluginDirectory, pluginName, pluginVersion, storedVersion } = params;

  await alert({
    app,
    message: translateFragment(($) => $.releaseNotes.versionMismatch.message, {
      pluginVersion: codeNode(pluginVersion),
      settingsFile: codeNode(`${pluginDirectory}/data.json`),
      storedVersion: codeNode(storedVersion)
    }),
    title: t(($) => $.releaseNotes.versionMismatch.title, { pluginName })
  });
}
