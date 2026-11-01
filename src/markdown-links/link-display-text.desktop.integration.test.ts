import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

import { findPluginSettingsComponent } from '../../scripts/helpers/plugin-settings-component-finder.ts';

/*
 * End-to-end coverage for issue #24: with `insertedLinkText` set to `{{attachmentFileName}}` (what the old
 * `Set link display text to attachment file name` toggle migrates into), generating a link to an EXISTING
 * attachment (via the patched `FileManager.generateMarkdownLink`, the sink every insert/drag/paste goes through)
 * sets its display text to the attachment's current base name (no extension), with no import in flight. Notes and
 * images are excluded; an explicit alias still wins. Blank by default -> no forced display text. Driven against the
 * real patched Obsidian API.
 */

interface LinkDisplayResult {
  readonly attachmentLinkOff: string;
  readonly attachmentLinkOn: string;
  readonly attachmentWithAliasOn: string;
  readonly imageBaseName: string;
  readonly imageLinkOn: string;
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
  it('sets attachment link display text to the base name, excludes notes and images, and respects a blank template', async () => {
    const result = await evalInObsidian({
      async callback({ app, findPluginSettingsComponent: findSettingsComponent }): Promise<LinkDisplayResult> {
        interface DisplayTextSettings {
          readonly attachmentFolderPath: string;
          // eslint-disable-next-line typescript-dev-toolkit/readonly-interface-members -- This member is reassigned by settings editors or mutable test fixtures.
          insertedLinkText: string;
        }

        function isDisplayTextSettings(value: unknown): value is DisplayTextSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['insertedLinkText'] === 'string'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        const settingsComponent = findSettingsComponent(app.plugins.getPlugin('obsidian-custom-attachment-location'), isDisplayTextSettings);
        if (!settingsComponent) {
          return {
            attachmentLinkOff: '',
            attachmentLinkOn: '',
            attachmentWithAliasOn: '',
            imageBaseName: '',
            imageLinkOn: '',
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
        const image = await app.vault.createBinary(`ldt-image-${stamp}.png`, new ArrayBuffer(4));

        const previousInsertedLinkText = settingsComponent.settings.insertedLinkText;
        await settingsComponent.editAndSave((settings) => {
          settings.insertedLinkText = '{{attachmentFileName}}';
        });

        try {
          const attachmentLinkOn = app.fileManager.generateMarkdownLink(pdf, note.path);
          const noteLinkOn = app.fileManager.generateMarkdownLink(otherNote, note.path);
          const imageLinkOn = app.fileManager.generateMarkdownLink(image, note.path);
          const attachmentWithAliasOn = app.fileManager.generateMarkdownLink(pdf, note.path, undefined, 'explicit-alias');

          await settingsComponent.editAndSave((settings) => {
            settings.insertedLinkText = '';
          });
          const attachmentLinkOff = app.fileManager.generateMarkdownLink(pdf, note.path);

          return {
            attachmentLinkOff,
            attachmentLinkOn,
            attachmentWithAliasOn,
            imageBaseName: image.basename,
            imageLinkOn,
            noteBaseName: otherNote.basename,
            noteLinkOn,
            pdfBaseName: pdf.basename,
            settingsFound: true
          };
        } finally {
          await settingsComponent.editAndSave((settings) => {
            settings.insertedLinkText = previousInsertedLinkText;
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

    // Images are excluded: an embed alias is its size, so a numeric base name would resize it.
    expect(result.imageLinkOn).not.toContain(`|${result.imageBaseName}`);

    // An explicit alias still wins over the template.
    expect(result.attachmentWithAliasOn).toContain('|explicit-alias');
    expect(result.attachmentWithAliasOn).not.toContain(`|${result.pdfBaseName}`);

    // Blank (default): no forced display text on the attachment link.
    expect(result.attachmentLinkOff).not.toContain(`|${result.pdfBaseName}`);
  }, 120_000);
});
