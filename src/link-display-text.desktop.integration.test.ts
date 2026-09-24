import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for issue #24 (an already-merged feature of this plugin): with
 * `shouldSetLinkDisplayTextToAttachmentFileName` ON, generating a link to an ATTACHMENT (via the
 * patched `FileManager.generateMarkdownLink`, the sink every insert/drag/paste goes through) sets its
 * display text to the attachment base name (no extension). Notes are excluded; an explicit alias
 * still wins. Off by default -> no forced display text. Driven against the real patched Obsidian API.
 */

interface LinkDisplayResult {
  readonly attachmentLinkOff: string;
  readonly attachmentLinkOn: string;
  readonly attachmentWithAliasOn: string;
  readonly noteBaseName: string;
  readonly noteLinkOn: string;
  readonly pdfBaseName: string;
  readonly settingsFound: boolean;
}

/*
 * Desktop-only: no Android emulator is available in this environment. The `generateMarkdownLink` patch is
 * cross-platform, so renaming this file to `*.cross-platform.integration.test.ts` lifts it to
 * Android once an emulator exists.
 */

describe('Link display text = attachment file name (issue #24)', () => {
  it('sets attachment link display text to the base name, excludes notes, and respects the toggle', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent }): Promise<LinkDisplayResult> {
        interface DisplayTextSettings {
          attachmentFolderPath: string;
          shouldSetLinkDisplayTextToAttachmentFileName: boolean;
        }

        function isDisplayTextSettings(value: unknown): value is DisplayTextSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldSetLinkDisplayTextToAttachmentFileName'] === 'boolean'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isDisplayTextSettings);
        if (!settingsComponent) {
          return {
            attachmentLinkOff: '',
            attachmentLinkOn: '',
            attachmentWithAliasOn: '',
            noteBaseName: '',
            noteLinkOn: '',
            pdfBaseName: '',
            settingsFound: false
          };
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const note = await app.vault.create(`ldt-note-${stamp}.md`, '');
        const otherNote = await app.vault.create(`ldt-other-${stamp}.md`, '');
        const pdf = await app.vault.createBinary(`ldt-doc-${stamp}.pdf`, new ArrayBuffer(4));

        const wasSettingLinkDisplayText = settingsComponent.settings.shouldSetLinkDisplayTextToAttachmentFileName;
        await settingsComponent.editAndSave((settings) => {
          settings.shouldSetLinkDisplayTextToAttachmentFileName = true;
        });

        try {
          const attachmentLinkOn = app.fileManager.generateMarkdownLink(pdf, note.path);
          const noteLinkOn = app.fileManager.generateMarkdownLink(otherNote, note.path);
          const attachmentWithAliasOn = app.fileManager.generateMarkdownLink(pdf, note.path, undefined, 'explicit-alias');

          await settingsComponent.editAndSave((settings) => {
            settings.shouldSetLinkDisplayTextToAttachmentFileName = false;
          });
          const attachmentLinkOff = app.fileManager.generateMarkdownLink(pdf, note.path);

          return {
            attachmentLinkOff,
            attachmentLinkOn,
            attachmentWithAliasOn,
            noteBaseName: otherNote.basename,
            noteLinkOn,
            pdfBaseName: pdf.basename,
            settingsFound: true
          };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.shouldSetLinkDisplayTextToAttachmentFileName = wasSettingLinkDisplayText;
          });
        }
      },
      input: { findPluginSettingsComponent },
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);

    // ON: the attachment link carries the attachment base name as its display text.
    expect(result.attachmentLinkOn).toContain(`|${result.pdfBaseName}`);

    // Notes are excluded: a note-to-note link gets no forced display text.
    expect(result.noteLinkOn).not.toContain(`|${result.noteBaseName}`);

    // An explicit alias still wins over the base-name default.
    expect(result.attachmentWithAliasOn).toContain('|explicit-alias');
    expect(result.attachmentWithAliasOn).not.toContain(`|${result.pdfBaseName}`);

    // OFF (default): no forced display text on the attachment link.
    expect(result.attachmentLinkOff).not.toContain(`|${result.pdfBaseName}`);
  }, 120_000);
});
