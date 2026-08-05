import { evalInObsidian } from 'obsidian-integration-testing';
import { getTempVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for issue #24 (G97 for an already-merged OCAL feature): with
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
      // eslint-disable-next-line unicorn/name-replacements -- `args` is an `obsidian-integration-testing` parameter name.
      args: {},
      // eslint-disable-next-line unicorn/name-replacements -- `fn` is an `obsidian-integration-testing` parameter name.
      async fn({ app }): Promise<LinkDisplayResult> {
        interface DisplayTextSettings {
          attachmentFolderPath: string;
          shouldSetLinkDisplayTextToAttachmentFileName: boolean;
        }

        function isDisplayTextSettings(value: unknown): value is DisplayTextSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['shouldSetLinkDisplayTextToAttachmentFileName'] === 'boolean'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        function findSettings(): DisplayTextSettings | null {
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
            if (isDisplayTextSettings(record['settings'])) {
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

        settings.shouldSetLinkDisplayTextToAttachmentFileName = true;
        const attachmentLinkOn = app.fileManager.generateMarkdownLink(pdf, note.path);
        const noteLinkOn = app.fileManager.generateMarkdownLink(otherNote, note.path);
        const attachmentWithAliasOn = app.fileManager.generateMarkdownLink(pdf, note.path, undefined, 'explicit-alias');

        settings.shouldSetLinkDisplayTextToAttachmentFileName = false;
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
      },
      vaultPath: getTempVault().path
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
