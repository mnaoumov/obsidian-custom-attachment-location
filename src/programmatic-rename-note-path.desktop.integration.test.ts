import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for the defect behind Advanced Note Composer issue #259: a PROGRAMMATIC
 * attachment-path resolution with `AttachmentPathContext.RenameNote` must never run the
 * generated-name template, and so must never open the `${prompt}` modal.
 *
 * The reporter saw it as "error when splitting recursively" — one `Rename attachment file` dialog per
 * created note, and `Error: Prompt cancelled` on cancel — but nothing about it is specific to that
 * plugin. `renamedAttachmentFileName` ships empty, so the resolver fell back to
 * `generatedAttachmentFileName`, and a `${prompt}` there opened a modal.
 *
 * This drives `vault.getAvailablePathForAttachments.extended` directly, which is exactly the surface
 * dev-utils' `getAttachmentFilePath` reaches and therefore exactly what Advanced Note Composer calls.
 * Going through the resolver rather than `app.fileManager.renameFile` is deliberate: renameFile stalls
 * on `metadataCache.onCleanCache` in the shared-instance aggregate (the documented headless wall that
 * forces the rename suites to `it.skip`), and it is not what this fix is about. The defect lives in
 * the resolution, so the resolution is what gets driven.
 *
 * Desktop-only: no Android emulator is available in this environment. The behavior is cross-platform,
 * so renaming this file to `*.cross-platform.integration.test.ts` lifts it to Android once one exists.
 */

interface ProgrammaticRenameResult {
  readonly errors: readonly string[];
  readonly pathWithRenamingOff: string;
  readonly pathWithRenamingOn: string;
  readonly probesFound: boolean;
  readonly wasPromptShown: boolean;
}

describe('Programmatic RenameNote resolution (Advanced Note Composer issue #259)', () => {
  it('keeps the attachment file name and opens no prompt, with attachment renaming off and on', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<ProgrammaticRenameResult> {
        interface ExtendedResolver {
          extended(params: ResolveParams): Promise<string>;
        }

        interface RenameNoteSettings {
          attachmentFolderPath: string;
          generatedAttachmentFileName: string;
          renamedAttachmentFileName: string;
        }

        /*
         * `shouldRenameAttachmentFiles` belongs to Advanced Rename and Delete Handler since 12.0.0, and
         * this plugin reads it back through that plugin's API. So the two phases below swap the
         * PROVIDER rather than the setting, by parking a stub on the read-back component's live ref —
         * which exercises the real read path without needing the other plugin installed in the vault.
         */
        interface HandedOverProvider {
          getSettings(): Record<string, unknown>;
          isPathIgnored(path: string): boolean;
          isTreatedAsAttachment(path: string): boolean;
        }

        interface HandedOverProviderRef {
          value: HandedOverProvider | null;
        }

        interface HandedOverSettingsHolder {
          apiRef: HandedOverProviderRef | null;
        }

        interface ResolveParams {
          readonly attachmentFileBaseName: string;
          readonly attachmentFileExtension: string;
          readonly context: string;
          readonly notePathOrFile: string;
          readonly oldAttachmentPathOrFile: string;
          readonly oldNotePathOrFile: string;
          readonly readAttachmentFileContent: null;
          readonly shouldSkipDuplicateCheck: boolean;
          readonly shouldSkipMissingAttachmentFolderCreation: boolean;
        }

        const EMPTY_RESULT = {
          errors: [],
          pathWithRenamingOff: '',
          pathWithRenamingOn: '',
          wasPromptShown: false
        };

        function hasExtendedResolver(value: unknown): value is ExtendedResolver {
          // Read the property before the `typeof value === 'function'` check narrows `value` to
          // `Function`, which carries no index signature to read `extended` off.
          const record = value as null | Record<string, unknown>;
          return typeof value === 'function' && typeof record?.['extended'] === 'function';
        }

        function isRenameNoteSettings(value: unknown): value is RenameNoteSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['renamedAttachmentFileName'] === 'string'
            && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        function isHandedOverSettingsHolder(value: unknown): value is HandedOverSettingsHolder {
          const record = value as null | Record<string, unknown>;
          return typeof value === 'object' && record !== null
            && 'apiRef' in record
            && typeof record['isPathIgnored'] === 'function'
            && typeof record['isTreatedAsAttachment'] === 'function';
        }

        // Neither the settings nor the read-back component is exposed publicly, so both are located by
        // Walking the plugin's component tree (same approach as the other OCAL integration tests).
        function findInPluginTree<T>(match: (record: Record<string, unknown>) => null | T): null | T {
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
            const matched = match(record);
            if (matched !== null) {
              return matched;
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

        const settings = findInPluginTree((record) => isRenameNoteSettings(record['settings']) ? record['settings'] : null);
        const foundHolder = findInPluginTree((record) => isHandedOverSettingsHolder(record) ? record : null);
        const resolver: unknown = app.vault.getAvailablePathForAttachments;
        if (!settings || !foundHolder || !hasExtendedResolver(resolver)) {
          return { ...EMPTY_RESULT, probesFound: false };
        }
        const holder: HandedOverSettingsHolder = foundHolder;

        // Mirrors this plugin's own absent-provider defaults, so only the value under test differs
        // Between the two phases.
        function stubProvider(shouldRenameAttachmentFiles: boolean): void {
          holder.apiRef = {
            value: {
              getSettings: (): Record<string, unknown> => ({
                emptyFolderBehavior: 'DeleteWithEmptyParents',
                notePriorities: [],
                shouldRenameAttachmentFiles,
                treatAsAttachmentExtensions: ['.excalidraw.md']
              }),
              isPathIgnored: (): boolean => false,
              isTreatedAsAttachment: (path: string): boolean => path.endsWith('.excalidraw.md')
            }
          };
        }

        // The narrowing above does not reach into the `resolve` closure below, so pin it to a typed const.
        const extendedResolver: ExtendedResolver = resolver;

        /*
         * These tests share one Obsidian instance with every other integration file, and the settings
         * object is the live one. Snapshot it and put it back — a leaked `${prompt}` template would
         * block the next test behind a modal nobody answers.
         */
        const originalSettings = {
          attachmentFolderPath: settings.attachmentFolderPath,
          generatedAttachmentFileName: settings.generatedAttachmentFileName,
          renamedAttachmentFileName: settings.renamedAttachmentFileName
        };
        const priorApiRef = holder.apiRef;
        function restoreSettings(currentSettings: RenameNoteSettings): void {
          currentSettings.attachmentFolderPath = originalSettings.attachmentFolderPath;
          currentSettings.generatedAttachmentFileName = originalSettings.generatedAttachmentFileName;
          currentSettings.renamedAttachmentFileName = originalSettings.renamedAttachmentFileName;
          holder.apiRef = priorApiRef;
        }

        // The reporter's configuration, and the shipped defaults for the two rename settings.
        settings.attachmentFolderPath = './@';
        // eslint-disable-next-line no-template-curly-in-string -- Intentional plugin token, not a JS template literal.
        settings.generatedAttachmentFileName = '${prompt}';
        settings.renamedAttachmentFileName = '';

        /*
         * Before the fix the resolution blocked on the modal, so a watcher both records that it opened
         * and dismisses it — otherwise a regression would hang the run instead of failing it.
         *
         * The selector is deliberately unscoped: any prompt modal on screen during this callback is
         * this test's, because the shared config sets `fileParallelism: false`, so no other integration
         * file — `prompt-input-focus`, which drives its own `${prompt}` modal, included — can be
         * mid-flight here. The interval is cleared before the callback returns.
         */
        let wasPromptShown = false;
        const watcherId = window.setInterval(() => {
          const modalEl = document.querySelector<HTMLElement>('.modal-container.prompt-modal');
          if (!modalEl) {
            return;
          }
          wasPromptShown = true;
          modalEl.querySelector<HTMLElement>('.cancel-button')?.click();
          modalEl.querySelector<HTMLElement>('.modal-close-button')?.click();
        }, 50);

        const errors: string[] = [];
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const folder = `t643-${stamp}`;
        await app.vault.createFolder(folder);
        await app.vault.createFolder(`${folder}/@`);
        await app.vault.createBinary(`${folder}/@/pic-${stamp}.png`, new ArrayBuffer(8));
        const note = await app.vault.create(`${folder}/note-${stamp}.md`, `![[@/pic-${stamp}.png]]`);

        async function resolve(): Promise<string> {
          try {
            return await extendedResolver.extended({
              attachmentFileBaseName: `pic-${stamp}`,
              attachmentFileExtension: 'png',
              // `AttachmentPathContext.RenameNote` — the enum is not importable inside this callback.
              context: 'RenameNote',
              notePathOrFile: `${folder}/renamed-${stamp}.md`,
              oldAttachmentPathOrFile: `${folder}/@/pic-${stamp}.png`,
              oldNotePathOrFile: note.path,
              readAttachmentFileContent: null,
              shouldSkipDuplicateCheck: true,
              shouldSkipMissingAttachmentFolderCreation: true
            });
          } catch (error) {
            errors.push(error instanceof Error ? error.message : String(error));
            return '';
          }
        }

        // Fix B: the resolver honors "do not rename attachment files".
        stubProvider(false);
        const pathWithRenamingOff = await resolve();

        // Fix A: an empty `renamedAttachmentFileName` means "keep the original name", not "fall back".
        stubProvider(true);
        const pathWithRenamingOn = await resolve();

        await sleep(300);
        window.clearInterval(watcherId);
        restoreSettings(settings);

        return {
          errors,
          pathWithRenamingOff,
          pathWithRenamingOn,
          probesFound: true,
          wasPromptShown
        };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(result.probesFound).toBe(true);
    expect(result.errors).toEqual([]);
    // The `${prompt}` modal is what the reporter saw once per created note. It must never open here.
    expect(result.wasPromptShown).toBe(false);
    // The attachment keeps its name; only the folder follows the note.
    expect(result.pathWithRenamingOff).toMatch(/^t643-[\d-]+\/@\/pic-[\d-]+\.png$/);
    expect(result.pathWithRenamingOn).toBe(result.pathWithRenamingOff);
  }, 120_000);
});
