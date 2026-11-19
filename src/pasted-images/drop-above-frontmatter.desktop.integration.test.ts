import { evalInObsidian } from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import {
  describe,
  expect,
  it
} from 'vitest';

/*
 * A file dropped above the editor's text, on the inline title or the Properties block, must not land above the
 * frontmatter.
 *
 * Obsidian's drop handler moves the selection to `posAtCoords` of the drop point, which answers `0` for any point
 * above the text, so the links went in before the opening `---`. The drop is dispatched for the reason
 * `screenshot-file-paste.desktop.integration.test.ts` gives: a trusted drop needs an OS drag from another application.
 * It still runs Obsidian's own drop handler, `insertFiles` and `saveAttachment`.
 */

interface DropResult {
  readonly error: string;
  readonly noteContent: string;
}

interface EditorLike {
  readonly cm?: EditorViewLike;
  readonly setCursor: (line: number, ch: number) => void;
}

interface EditorViewLike {
  readonly contentDOM: HTMLElement;
}

interface MarkdownViewLike {
  readonly editor?: EditorLike;
}

const BODY_LINE = 'Body line';

describe('a file dropped above the editor text', () => {
  it.each([
    { isSourceMode: true, modeName: 'Source mode' },
    { isSourceMode: false, modeName: 'Live Preview' }
  ])('goes in at the cursor in the body, never above the frontmatter, in $modeName', async ({ isSourceMode }) => {
    const result = await evalInObsidian({
      async callback({ app, bodyLine, isSourceMode: isSource, lib: { waitUntil } }): Promise<DropResult> {
        const stamp = `${Date.now().toString()}-${Math.floor(performance.now()).toString()}`;
        const note = await app.vault.create(`drop-above-frontmatter-${stamp}.md`, `---\ntags: a\n---\n${bodyLine}\n`);
        const leaf = app.workspace.getLeaf(true);
        try {
          await leaf.openFile(note, { state: { mode: 'source', source: isSource } });
          await app.workspace.revealLeaf(leaf);
          app.workspace.setActiveLeaf(leaf, { focus: true });
          await sleep(500);

          const viewUnknown: unknown = leaf.view;
          const editor = (viewUnknown as MarkdownViewLike).editor;
          const contentDom = editor?.cm?.contentDOM;
          if (!editor || !contentDom) {
            return { error: 'no editor content DOM', noteContent: '' };
          }
          contentDom.focus();
          // After `Body`.
          editor.setCursor(3, 4);

          const file = new File(['dropped'], `dropped-${stamp}.txt`, { type: 'text/plain' });
          const dataTransfer = new DataTransfer();
          dataTransfer.items.add(file);
          const rect = contentDom.getBoundingClientRect();
          // eslint-disable-next-line obsidian-dev-toolkit/no-untrusted-input-events -- `sendInputEvent` cannot express a drag; the wait below fails unless Obsidian really saved the dropped file.
          contentDom.dispatchEvent(
            new DragEvent('drop', {
              bubbles: true,
              cancelable: true,
              clientX: rect.left + 5,
              // Above the text: where the inline title and the Properties block are.
              clientY: rect.top - 20,
              dataTransfer
            })
          );

          const SAVE_TIMEOUT_IN_MILLISECONDS = 10_000;
          await waitUntil({
            message: 'the dropped file to be saved and linked',
            predicate: async () => {
              const content = await app.vault.read(note);
              return content.includes(`dropped-${stamp}`);
            },
            timeoutInMilliseconds: SAVE_TIMEOUT_IN_MILLISECONDS
          });

          return { error: '', noteContent: await app.vault.read(note) };
        } catch (error) {
          return { error: String(error), noteContent: '' };
        } finally {
          leaf.detach();
        }
      },
      input: { bodyLine: BODY_LINE, isSourceMode },
      vaultPath: getTemporaryVault().path
    });

    expect(result.error).toBe('');
    // The cursor was after `Body`, and the link goes in exactly there.
    expect(result.noteContent, result.noteContent).toMatch(/^---\ntags: a\n---\nBody!\[\[dropped-[\d-]+\.txt\]\] line\n$/);
  }, 60_000);
});
