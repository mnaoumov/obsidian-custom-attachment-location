import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * End-to-end coverage for the first and third halves of issue #59 (G97): the `${prompt}` modal must
 * open with its input already focused and its default value pre-selected, so typing replaces the name
 * without a click first — and its heading must say what is actually being decided.
 *
 * The modal is driven through its real DOM (fill the input, click the OK button) rather than stubbed,
 * per G97. `document.activeElement` is asserted inside the live renderer, which is the only place the
 * focus is real — the unit test can only observe the `focus()` call, since the mock modal never
 * attaches its content to a document.
 *
 * Desktop-only: no Android emulator is available in this environment. The behavior is cross-platform,
 * so renaming this file to `*.cross-platform.integration.test.ts` lifts it to Android once one exists.
 */

interface PromptFocusResult {
  readonly heading: string;
  readonly isInputFocused: boolean;
  readonly savedPaths: readonly string[];
  readonly selectedText: string;
  readonly settingsFound: boolean;
  readonly value: string;
}

describe('The prompt token modal (issue #59)', () => {
  it('opens focused with the default value selected, names the rename, and saves what is typed', async () => {
    const result = await evalInObsidian({
      async callback({ app }): Promise<PromptFocusResult> {
        interface PromptSettings {
          attachmentFolderPath: string;
          attachmentRenameMode: string;
          generatedAttachmentFileName: string;
        }

        const EMPTY_RESULT = {
          heading: '',
          isInputFocused: false,
          savedPaths: [],
          selectedText: '',
          value: ''
        };

        function isPromptSettings(value: unknown): value is PromptSettings {
          return typeof value === 'object' && value !== null
            && typeof (value as Record<string, unknown>)['attachmentRenameMode'] === 'string'
            && typeof (value as Record<string, unknown>)['generatedAttachmentFileName'] === 'string'
            && typeof (value as Record<string, unknown>)['attachmentFolderPath'] === 'string';
        }

        function findSettings(): null | PromptSettings {
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
            if (isPromptSettings(record['settings'])) {
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

        async function waitForPromptModal(): Promise<HTMLElement | null> {
          const deadline = Date.now() + 15_000;
          while (Date.now() < deadline) {
            // `addPluginCssClasses` marks the modal's `containerEl`, so the class is ON the
            // `.modal-container`, not on a descendant of it.
            const modalEl = document.querySelector<HTMLElement>('.modal-container.prompt-modal');
            /*
             * The OK button is built after the input, and the focus is applied last of all, so waiting
             * on the button (plus a settle) is what makes reading `activeElement` meaningful rather
             * than a race against the modal still assembling itself.
             */
            if (modalEl?.querySelector('input') && modalEl.querySelector('.ok-button')) {
              await sleep(300);
              return modalEl;
            }
            await sleep(100);
          }
          return null;
        }

        const settings = findSettings();
        if (!settings) {
          return { ...EMPTY_RESULT, settingsFound: false };
        }

        /*
         * These tests share one Obsidian instance with every other integration file, and the settings
         * object is the live one. Snapshot it and put it back — a leaked `${prompt}` template would
         * block the next test behind a modal nobody answers.
         */
        const originalSettings = {
          attachmentFolderPath: settings.attachmentFolderPath,
          attachmentRenameMode: settings.attachmentRenameMode,
          generatedAttachmentFileName: settings.generatedAttachmentFileName
        };
        function restoreSettings(currentSettings: PromptSettings): void {
          currentSettings.attachmentFolderPath = originalSettings.attachmentFolderPath;
          currentSettings.attachmentRenameMode = originalSettings.attachmentRenameMode;
          currentSettings.generatedAttachmentFileName = originalSettings.generatedAttachmentFileName;
        }

        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        settings.attachmentRenameMode = 'All';
        settings.attachmentFolderPath = './';
        // eslint-disable-next-line no-template-curly-in-string -- Intentional plugin token, not a JS template literal.
        settings.generatedAttachmentFileName = '${prompt}';

        const note = await app.vault.create(`prompt-note-${stamp}.md`, '');
        const leaf = app.workspace.getLeaf(false);
        await leaf.openFile(note);
        await app.workspace.revealLeaf(leaf);
        await sleep(500);

        const originalBaseName = `original-${stamp}`;
        /*
         * `saveAttachment` is the sink the plugin patches; it reaches the same `${prompt}` evaluation
         * a real paste does, without needing a synthetic clipboard event.
         */
        const savePromise = app.saveAttachment(originalBaseName, 'png', new ArrayBuffer(8));

        const modalEl = await waitForPromptModal();
        if (!modalEl) {
          restoreSettings(settings);
          return { ...EMPTY_RESULT, settingsFound: true };
        }

        const inputEl = modalEl.querySelector('input');
        if (!inputEl) {
          restoreSettings(settings);
          return { ...EMPTY_RESULT, settingsFound: true };
        }

        // Issue #59 part 1: the caret must already be in the box, with the existing name selected.
        const isInputFocused = document.activeElement === inputEl;

        const selectedText = inputEl.value.slice(inputEl.selectionStart ?? 0, inputEl.selectionEnd ?? 0);
        const value = inputEl.value;
        /*
         * Issue #59 part 3: the heading names the decision. The title is a fragment — the heading text
         * node, a `<br>`, then the template preview — and the first node is read because `textContent`
         * would run the two lines together, a `<br>` being no newline.
         */
        const heading = modalEl.querySelector('.modal-title')?.firstChild?.textContent ?? '';

        const typedBaseName = `typed-${stamp}`;
        inputEl.value = typedBaseName;
        inputEl.dispatchEvent(new Event('input', { bubbles: true }));
        modalEl.querySelector<HTMLElement>('.ok-button')?.click();

        await savePromise;
        await sleep(500);

        const savedPaths = app.vault.getFiles()
          .map((file) => file.path)
          .filter((path) => path.includes(stamp) && path.endsWith('.png'));

        leaf.detach();
        restoreSettings(settings);

        return {
          heading,
          isInputFocused,
          savedPaths,
          selectedText,
          settingsFound: true,
          value
        };
      },
      input: {},
      vaultPath: getTemporaryVault().path
    });

    expect(result.settingsFound).toBe(true);
    expect(result.isInputFocused).toBe(true);
    // The whole default value is selected, so the first keystroke replaces it.
    expect(result.selectedText).toBe(result.value);
    expect(result.value).toMatch(/^original-/);
    expect(result.heading).toBe('Rename attachment file');
    expect(result.savedPaths).toHaveLength(1);
    expect(result.savedPaths[0]).toMatch(/^typed-[\d-]+\.png$/);
  }, 120_000);
});
