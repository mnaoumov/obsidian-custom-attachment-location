import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * Asserts what each demo-vault `Try it` section promises the reader.
 *
 * The button suite beside this file clicks every button and fails only on one that errors or never reports,
 * so a button that runs cleanly while the vault ends up somewhere other than the note says would pass it.
 * The buttons are one-line calls into `demo-vault/_assets/CodeScriptToolkit/demoSetup.ts`, so this calls the
 * SAME helpers, in the order the note presents them, through `CodeScript Toolkit`'s global `requireAsync`,
 * and checks the vault after each step against the sentence the note wrote about it.
 *
 * Each demo recreates its own folder under `Materials/` and sets every setting it depends on, so the order
 * these run in, and whatever the button suite left behind, does not matter.
 *
 * Isolation: `npx vitest run --project integration-tests:demo-vault src/demo-vault/demo-vault-try-it.demo-vault.integration.test.ts`.
 */

declare global {
  interface Window {
    /**
     * Installed by `CodeScript Toolkit` when it loads. Resolves a `/`-rooted id against its modules root.
     */
    requireAsync?: (id: string) => Promise<Record<string, unknown>>;
  }
}

interface CallResult {
  readonly error: null | string;
  readonly notices: string[];
  readonly value: unknown;
}

interface CollectDemoReport {
  readonly files: string[];
}

interface CollectStepResult extends CollectDemoReport {
  readonly notices: string[];
}

interface DemoCall {
  readonly functionName: string;
  readonly helperArguments: unknown[];
}

interface LinkDisplayTextDemoReport {
  readonly attachmentLink: string;
  readonly noteLink: string;
}

interface TieDemoReport {
  readonly listedNotes: string[];
}

const COLLECT_MATERIALS_FOLDER_PATH = 'Materials/05 Collect attachments';
const TEST_TIMEOUT_IN_MILLISECONDS = 120_000;

describe('sidecar naming demo', () => {
  it('imports a companion named after the randomly named document', async () => {
    const result = await callDemoSetup({ functionName: 'saveSidecarDemo', helperArguments: [] });
    expect(result.error).toBeNull();
    expect(result.value).toEqual([expect.stringMatching(/\.html\.p7s$/u), expect.stringMatching(/\.html$/u)]);
    if (!Array.isArray(result.value) || typeof result.value[1] !== 'string') {
      throw new TypeError('Demo did not return its two saved paths');
    }
    expect(result.value[0]).toBe(`${result.value[1]}.p7s`);
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});

describe('original-name link text demo', () => {
  it('shows the arrival name beside a renamed PDF only while enabled', async () => {
    const enabled = await callDemoSetup({ functionName: 'insertOriginalNameLinkDemo', helperArguments: [true] });
    expect(enabled.error).toBeNull();
    expect(enabled.value).toContain('renamed-report.pdf');
    expect(enabled.value).toMatch(/\|report-2026\]\]|\[report-2026\]\(/);
    const disabled = await callDemoSetup({ functionName: 'insertOriginalNameLinkDemo', helperArguments: [false] });
    expect(disabled.error).toBeNull();
    expect(disabled.value).not.toContain('|report-2026');
    expect(disabled.value).not.toContain('[report-2026]');
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});

/**
 * Calls one exported `demoSetup.ts` helper inside Obsidian, as a button would, and captures the notices it
 * raised.
 *
 * @param call - The helper and its arguments after `app`.
 * @returns What it returned, the notices it showed, and the error it threw, if any.
 */
async function callDemoSetup(call: DemoCall): Promise<CallResult> {
  return await evalInObsidian({
    async callback({ app, functionName, helperArguments, lib: { waitUntil } }): Promise<CallResult> {
      // `CodeScript Toolkit` installs `requireAsync` when it loads, which can still be under way.
      const REQUIRE_WAIT_TIMEOUT_IN_MILLISECONDS = 10_000;
      try {
        await waitUntil({
          message: '`CodeScript Toolkit` never installed requireAsync',
          predicate: () => !!window.requireAsync,
          timeoutInMilliseconds: REQUIRE_WAIT_TIMEOUT_IN_MILLISECONDS
        });
      } catch (error) {
        return { error: String(error), notices: [], value: null };
      }

      const noticesBefore = new Set(document.querySelectorAll('.notice'));
      try {
        const demoSetup = await window.requireAsync?.('/demoSetup.ts') ?? {};
        const helper = demoSetup[functionName];
        if (typeof helper !== 'function') {
          return { error: `demoSetup.ts exports no ${functionName}`, notices: [], value: null };
        }
        const value: unknown = await (helper as (...callArguments: unknown[]) => Promise<unknown>)(app, ...helperArguments);
        const notices = [...document.querySelectorAll('.notice')]
          .filter((notice) => !noticesBefore.has(notice))
          .map((notice) => notice.textContent);
        return { error: null, notices, value: value ?? null };
      } catch (error) {
        return { error: error instanceof Error ? error.stack ?? error.message : String(error), notices: [], value: null };
      }
    },
    input: {
      functionName: call.functionName,
      helperArguments: call.helperArguments
    },
    vaultPath: getTemporaryVault().path
  });
}

/**
 * Dismisses every open dialog with `Escape`, as the reader would.
 *
 * The shared-attachment dialog has no close button, so `Escape` is the one way to dismiss it without
 * choosing a mode. It answers `Cancel`.
 *
 * @returns How many dialogs are still open.
 */
async function dismissModals(): Promise<number> {
  return await evalInObsidian({
    async callback({ lib: { pressKey, waitUntil } }): Promise<number> {
      if (document.querySelector('.modal-container')) {
        // Sized under the transport's 30 s cap: a dialog closes on the next frame.
        const CLOSE_WAIT_TIMEOUT_IN_MILLISECONDS = 5000;
        await pressKey({ key: 'Escape' });
        try {
          await waitUntil({
            message: 'the dialog did not close on Escape',
            predicate: () => !document.querySelector('.modal-container'),
            timeoutInMilliseconds: CLOSE_WAIT_TIMEOUT_IN_MILLISECONDS
          });
        } catch {
          // Reported through the count below.
        }
      }
      return document.querySelectorAll('.modal-container').length;
    },
    vaultPath: getTemporaryVault().path
  });
}

/**
 * Asserts the files a demo folder holds, in any order.
 *
 * @param report - What the helper reported.
 * @param expectedFiles - The files the note says the folder holds, relative to it.
 */
function expectFiles(report: CollectDemoReport, expectedFiles: string[]): void {
  expect([...report.files].sort()).toEqual([...expectedFiles].sort());
}

/**
 * Whether a note's links resolve to a file, waiting for Obsidian to re-index a note collecting just rewrote.
 *
 * Asked of the resolver rather than of the note's text, because the link text depends on the vault's link
 * format and on which other files share the name.
 *
 * @param notePath - The note.
 * @param targetPath - The file its link should now reach.
 * @returns Whether it does.
 */
async function isLinkResolved(notePath: string, targetPath: string): Promise<boolean> {
  return await evalInObsidian({
    async callback({ app, lib: { waitUntil }, linkTargetPath, sourcePath }): Promise<boolean> {
      // Sized under the transport's 30 s cap: a rewritten note is re-indexed within a second.
      const RESOLVE_WAIT_TIMEOUT_IN_MILLISECONDS = 5000;
      try {
        await waitUntil({
          message: `${sourcePath} does not link to ${linkTargetPath}`,
          predicate: () => Object.hasOwn(app.metadataCache.resolvedLinks[sourcePath] ?? {}, linkTargetPath),
          timeoutInMilliseconds: RESOLVE_WAIT_TIMEOUT_IN_MILLISECONDS
        });
        return true;
      } catch {
        return false;
      }
    },
    input: { linkTargetPath: targetPath, sourcePath: notePath },
    vaultPath: getTemporaryVault().path
  });
}

/**
 * Opens a walkthrough note, which is the note the reader presses its buttons in.
 *
 * @param path - The note's path from the vault root.
 */
async function openNote(path: string): Promise<void> {
  await evalInObsidian({
    async callback({ app, notePath }): Promise<void> {
      const file = app.vault.getFileByPath(notePath);
      if (file) {
        await app.workspace.getLeaf(false).openFile(file);
      }
    },
    input: { notePath: path },
    vaultPath: getTemporaryVault().path
  });
}

/**
 * Runs a collect-demo helper and returns the files its folder holds afterwards.
 *
 * @param functionName - `setUpCollectDemo` or `collectInDemo`.
 * @param helperArguments - Its arguments after `app`.
 * @returns The files, relative to the demo's folder, and the notices.
 */
async function runCollectStep(functionName: 'collectInDemo' | 'setUpCollectDemo', ...helperArguments: unknown[]): Promise<CollectStepResult> {
  const result = await runStepWithNotices(functionName, ...helperArguments);
  const report = result.value as CollectDemoReport;
  return { files: report.files, notices: result.notices };
}

/**
 * Runs a helper and returns what it returned.
 *
 * @param functionName - The exported helper.
 * @param helperArguments - Its arguments after `app`.
 * @returns Its value.
 */
async function runStep<T>(functionName: string, ...helperArguments: unknown[]): Promise<T> {
  const result = await runStepWithNotices(functionName, ...helperArguments);
  return result.value as T;
}

/**
 * Runs a helper and fails the test with its error if it threw.
 *
 * @param functionName - The exported helper.
 * @param helperArguments - Its arguments after `app`.
 * @returns What it returned, and the notices it showed.
 */
async function runStepWithNotices(functionName: string, ...helperArguments: unknown[]): Promise<CallResult> {
  const result = await callDemoSetup({ functionName, helperArguments });
  expect(result.error, `${functionName} threw`).toBeNull();
  return result;
}

describe('05 Collect attachments', () => {
  it('collects an attachment into the folder the location pattern names, and follows a changed pattern', async () => {
    expectFiles(await runCollectStep('setUpCollectDemo', 'basic'), ['Collect demo.md', 'loose/image.png']);
    expectFiles(await runCollectStep('collectInDemo', 'basic'), ['assets/Collect demo/image.png', 'Collect demo.md']);

    await runStep('changeSettings', { attachmentFolderPath: './attachments' });
    expectFiles(await runCollectStep('collectInDemo', 'basic'), ['attachments/image.png', 'Collect demo.md']);
  }, TEST_TIMEOUT_IN_MILLISECONDS);

  it('collects into a destination of its own, while a paste keeps using the location for new attachments', async () => {
    await runCollectStep('setUpCollectDemo', 'destination');
    expectFiles(await runCollectStep('collectInDemo', 'destination'), ['_Attachments/image.png', 'Example Note.md']);

    await runStep('changeSettings', { collectedAttachmentFolderPath: './{{noteFileName}}.assets' });
    expectFiles(await runCollectStep('collectInDemo', 'destination'), ['Example Note.assets/image.png', 'Example Note.md']);

    const afterPaste = await runStep<CollectDemoReport>('pasteIntoDestinationDemo');
    expect(afterPaste.files).toHaveLength(3);
    expect(afterPaste.files).toContain('Example Note.assets/image.png');
    expect(afterPaste.files.filter((file) => file.startsWith('_Attachments/'))).toHaveLength(1);
  }, TEST_TIMEOUT_IN_MILLISECONDS);

  it('moves an attachment referenced by a raw path only while the safety net is off', async () => {
    await runCollectStep('setUpCollectDemo', 'rawPath');
    expectFiles(await runCollectStep('collectInDemo', 'rawPath'), ['assets/Embed/raw-demo.png', 'Embed.md', 'raw-ref.md']);

    await runCollectStep('setUpCollectDemo', 'rawPath', { shouldSkipCollectingAttachmentsReferencedByRawPath: true });
    const skipped = await runCollectStep('collectInDemo', 'rawPath');
    expectFiles(skipped, ['Embed.md', 'raw-demo.png', 'raw-ref.md']);
    expect(skipped.notices.some((notice) => notice.includes('referenced by a raw path'))).toBe(true);
  }, TEST_TIMEOUT_IN_MILLISECONDS);

  it('keeps one copy of identical attachments only while deduplication is on', async () => {
    const notes = ['a/Note A.md', 'b/Note B.md'];

    await runCollectStep('setUpCollectDemo', 'dedupe');
    expectFiles(await runCollectStep('collectInDemo', 'dedupe', notes), ['_Attachments/image 1.png', '_Attachments/image.png', 'a/Note A.md', 'b/Note B.md']);

    await runCollectStep('setUpCollectDemo', 'dedupe', { shouldDeduplicateIdenticalAttachments: true });
    expectFiles(await runCollectStep('collectInDemo', 'dedupe', notes), ['_Attachments/image.png', 'a/Note A.md', 'b/Note B.md']);
    expect(await isLinkResolved(`${COLLECT_MATERIALS_FOLDER_PATH}/Dedupe demo/b/Note B.md`, `${COLLECT_MATERIALS_FOLDER_PATH}/Dedupe demo/_Attachments/image.png`))
      .toBe(true);
  }, TEST_TIMEOUT_IN_MILLISECONDS);

  it('moves a whole attachment unit folder only once it is designated', async () => {
    await runCollectStep('setUpCollectDemo', 'unitFolder');
    expectFiles(await runCollectStep('collectInDemo', 'unitFolder'), ['assets/Saved page/logo.png', 'Saved page.md', 'saved-page/page_files/style.css']);

    await runCollectStep('setUpCollectDemo', 'unitFolder', { attachmentUnitFolderPaths: [`${COLLECT_MATERIALS_FOLDER_PATH}/Unit folder demo/saved-page/page_files`] });
    expectFiles(await runCollectStep('collectInDemo', 'unitFolder'), [
      'assets/Saved page/page_files/logo.png',
      'assets/Saved page/page_files/style.css',
      'Saved page.md'
    ]);
  }, TEST_TIMEOUT_IN_MILLISECONDS);

  it('hands a shared attachment to the highest-priority note, and asks only between the notes that tie', async () => {
    await runCollectStep('setUpCollectDemo', 'priorities');
    expectFiles(await runCollectStep('collectInDemo', 'priorities'), ['Drawing.excalidraw.md', 'Note.md', 'shared.png']);

    await runStep('changeNotePriorities', ['.md', '.excalidraw.md']);
    const fromDrawing = await runCollectStep('collectInDemo', 'priorities', ['Drawing.excalidraw.md']);
    expectFiles(fromDrawing, ['assets/Note/shared.png', 'Drawing.excalidraw.md', 'Note.md']);
    expect(fromDrawing.notices.some((notice) => notice.includes('higher priority') && notice.includes('Note'))).toBe(true);

    const fromNote = await runCollectStep('collectInDemo', 'priorities');
    expectFiles(fromNote, ['assets/Note/shared.png', 'Drawing.excalidraw.md', 'Note.md']);
    expect(fromNote.notices.some((notice) => notice.includes('higher priority'))).toBe(false);

    try {
      const tie = await runStep<TieDemoReport>('collectPrioritiesTie');
      expect(tie.listedNotes).toHaveLength(2);
      expect(tie.listedNotes.join('\n')).not.toContain('Drawing');
    } finally {
      // The dialog holds the collect queue until it is answered, so every later collect would wait on it.
      expect(await dismissModals()).toBe(0);
      await runStep('restoreCollectSettings');
    }
  }, TEST_TIMEOUT_IN_MILLISECONDS);

  it('collects a shared file whose extension is listed, and still skips the other types', async () => {
    await runCollectStep('setUpCollectDemo', 'extensions');
    expectFiles(await runCollectStep('collectInDemo', 'extensions'), ['Note A.md', 'Note B.md', 'shared.af', 'shared.png']);

    await runCollectStep('setUpCollectDemo', 'extensions', { excludeExtensionsFromMultipleNotesCheck: ['af'] });
    expectFiles(await runCollectStep('collectInDemo', 'extensions'), ['assets/Note A/shared.af', 'Note A.md', 'Note B.md', 'shared.png']);
    expect(
      await isLinkResolved(`${COLLECT_MATERIALS_FOLDER_PATH}/Shared type demo/Note B.md`, `${COLLECT_MATERIALS_FOLDER_PATH}/Shared type demo/assets/Note A/shared.af`)
    ).toBe(true);

    await runStep('restoreCollectSettings');
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});

describe('02 Attachment file naming, 04 Custom tokens', () => {
  it('names a sample attachment the way a paste would, with the default pattern and with custom tokens', async () => {
    await openNote('02 Attachment file naming.md');
    await runStep('restoreDefaultPatterns');
    expect(await runStep<string>('saveSampleAttachment', { kind: 'image' })).toMatch(/^assets\/02 Attachment file naming\/file-\d{17}\.png$/u);

    await openNote('04 Custom tokens.md');
    await runStep('registerExampleTokens');
    expect(await runStep<string>('previewAttachmentPath')).toMatch(/^assets\/04 Custom tokens\/04 Custom tokens.*defaultFormatValue.*\.png$/u);

    await runStep('registerImagesOnlyToken');
    expect(await runStep<string>('saveSampleAttachment', { kind: 'image' })).toMatch(/^assets\/04 Custom tokens\/04 Custom tokens-\d{17}\.png$/u);
    // The button suite may have saved one already, in which case this one takes the next free name.
    expect(await runStep<string>('saveSampleAttachment', { kind: 'pdf' })).toMatch(/^assets\/04 Custom tokens\/report-2026(?: \d+)?\.pdf$/u);

    await runStep('removeExampleTokens');
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});

describe('07 Link display text', () => {
  it('gives an attachment link the attachment\'s name as its text, and leaves a note link alone', async () => {
    await runStep('changeSettings', { shouldSetLinkDisplayTextToAttachmentFileName: false });
    const before = await runStep<LinkDisplayTextDemoReport>('insertLinksForDisplayTextDemo');
    expect(before.attachmentLink).not.toContain('|report-2026]]');

    await runStep('changeSettings', { shouldSetLinkDisplayTextToAttachmentFileName: true });
    const after = await runStep<LinkDisplayTextDemoReport>('insertLinksForDisplayTextDemo');
    expect(after.attachmentLink).toContain('report-2026.pdf|report-2026]]');
    expect(after.noteLink).toBe(before.noteLink);

    await runStep('changeSettings', { shouldSetLinkDisplayTextToAttachmentFileName: false });
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});

describe('10 Navigation', () => {
  it('goes from the note to its attachment folder and from the image back to the note', async () => {
    const notePath = await runStep<string>('setUpNavigationDemo');
    await runStep('goToNavigationDemoAttachmentFolder');
    expect(await runStep<null | string>('goToNavigationDemoOwningNote')).toBe(notePath);
  }, TEST_TIMEOUT_IN_MILLISECONDS);
});
