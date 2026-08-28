import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

interface ObsidianDevUtilsGlobal {
  readonly __obsidianDevUtils?: Record<string, OperationQueueWrapper | undefined>;
}

/**
 * The obsidian-dev-utils global operation queue, as seen from outside the library.
 *
 * Only the shape read here is modeled; the library does not export the type. Declared at module scope
 * because types are erased before the callback is serialized into Obsidian.
 */
interface OperationQueueState {
  readonly items?: readonly unknown[];
}

interface OperationQueueWrapper {
  readonly value?: OperationQueueState;
}

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
  /**
   * What held the focus when the modal opened, for the assertion message.
   */
  readonly activeElementDescription: string;
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

        // How long a cancelled `saveAttachment` is given to unwind before this gives up on it.
        const ABANDON_TIMEOUT_IN_MILLISECONDS = 5000;
        const QUEUE_DRAIN_POLL_IN_MILLISECONDS = 100;
        const QUEUE_DRAIN_TIMEOUT_IN_MILLISECONDS = 15_000;

        const EMPTY_RESULT = {
          activeElementDescription: '',
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
             * The OK button is built after the input, and the focus and selection are applied last of
             * all. Waiting for the focus ITSELF — rather than for the markup plus a fixed settle — is
             * what makes reading `activeElement` meaningful: a fixed sleep is a race that a loaded
             * machine loses, while this only ever returns early, never late. The assertion still holds
             * its meaning, because a modal that never focuses its input runs out the deadline below
             * and is reported exactly as the unfocused modal issue #59 is about.
             */
            const inputEl = modalEl?.querySelector('input');
            if (inputEl && modalEl?.querySelector('.ok-button')) {
              const isFocusedAndSelected = document.activeElement === inputEl
                && (inputEl.selectionEnd ?? 0) > (inputEl.selectionStart ?? 0);
              if (isFocusedAndSelected || Date.now() >= deadline - 100) {
                return modalEl;
              }
            }
            await sleep(100);
          }
          return null;
        }

        const foundSettings = findSettings();
        if (!foundSettings) {
          return { ...EMPTY_RESULT, settingsFound: false };
        }

        // A narrowed `const` does not stay narrowed inside a function declaration below it.
        const settings: PromptSettings = foundSettings;

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

        /*
         * Creating and opening the note above queues the plugin's own create/open handling on
         * obsidian-dev-utils' GLOBAL operation queue, which runs one entry at a time. `saveAttachment`
         * below lands BEHIND those entries, and the prompt modal only opens once its entry starts —
         * so triggering while the queue is busy is what made the modal miss the wait below entirely,
         * reported (misleadingly) as the input not being focused.
         */
        async function waitForQueueToDrain(): Promise<void> {
          const queueState = (window as ObsidianDevUtilsGlobal).__obsidianDevUtils?.['queue']?.value;
          const queueDeadline = Date.now() + QUEUE_DRAIN_TIMEOUT_IN_MILLISECONDS;
          while ((queueState?.items?.length ?? 0) > 0 && Date.now() < queueDeadline) {
            await sleep(QUEUE_DRAIN_POLL_IN_MILLISECONDS);
          }
        }
        await waitForQueueToDrain();

        const originalBaseName = `original-${stamp}`;
        /*
         * `saveAttachment` is the sink the plugin patches; it reaches the same `${prompt}` evaluation
         * a real paste does, without needing a synthetic clipboard event.
         */
        const savePromise = app.saveAttachment(originalBaseName, 'png', new ArrayBuffer(8));

        /*
         * Whatever happens from here on, the modal has to be ANSWERED and `savePromise` awaited before
         * this returns. `saveAttachment` is queued inside the plugin, and a modal left standing keeps
         * that queue entry pending forever — every later attachment operation, in this file and in
         * every file sharing this Obsidian instance, then waits behind it and times out. A whole run's
         * worth of unrelated suites failing in a row traces back to exactly this kind of early return.
         */
        async function abandon(): Promise<void> {
          // Its own close affordance, not its content buttons: cancelling is what resolves the queued
          // Save, while clicking blindly would activate whatever the dialog happens to offer.
          for (const closeEl of document.querySelectorAll<HTMLElement>('.modal-container .modal-close-button')) {
            closeEl.click();
          }
          await Promise.race([savePromise.catch(() => undefined), sleep(ABANDON_TIMEOUT_IN_MILLISECONDS)]);
          restoreSettings(settings);
        }

        const modalEl = await waitForPromptModal();
        if (!modalEl) {
          await abandon();
          return { ...EMPTY_RESULT, settingsFound: true };
        }

        const inputEl = modalEl.querySelector('input');
        if (!inputEl) {
          await abandon();
          return { ...EMPTY_RESULT, settingsFound: true };
        }

        // Issue #59 part 1: the caret must already be in the box, with the existing name selected.
        const isInputFocused = document.activeElement === inputEl;
        // What holds the focus instead, for the assertion message. A bare `false` cannot distinguish
        // "focus never applied" from "something else took it back".
        const activeElementDescription = `${document.activeElement?.tagName ?? 'none'}.${document.activeElement?.className ?? ''}`;

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
          activeElementDescription,
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
    expect(result.isInputFocused, `focus was on ${result.activeElementDescription}`).toBe(true);
    // The whole default value is selected, so the first keystroke replaces it.
    expect(result.selectedText).toBe(result.value);
    expect(result.value).toMatch(/^original-/);
    expect(result.heading).toBe('Rename attachment file');
    expect(result.savedPaths).toHaveLength(1);
    expect(result.savedPaths[0]).toMatch(/^typed-[\d-]+\.png$/);
  }, 120_000);
});
