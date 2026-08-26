/**
 * @file
 *
 * Produces the desktop screenshots the community-store listing needs
 * (T461-P21), driving a staged vault in a real Obsidian and writing
 * `images/screenshots/screenshot-desktop-N.png`.
 *
 * FIVE shots of the problem the README opens with: attachments that pile up in
 * one folder under names that say nothing, and then get left behind when the
 * note moves. Shot 1 is that pile, taken with the plugin DISABLED so it is the
 * reader's own vault rather than a caricature; shots 2 to 5 are the plugin
 * answering it.
 *
 * Every attachment here is saved the way Obsidian saves a pasted one: through
 * `app.saveAttachment`, the sink Obsidian's own paste handler calls and the one
 * the plugin patches. Nothing is written to a path this suite chose — the frames
 * show where the file actually landed, under the name it actually got.
 */

import {
  mkdirSync,
  writeFileSync
} from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';
import {
  captureObsidianScreenshot,
  evalInObsidian,
  labelScreenshot,
  readPngDimensions
} from 'obsidian-integration-testing';
import { getTemporaryVault } from 'obsidian-integration-testing/vitest-global-setup-plugin';
import { sharp } from 'sharp';
import {
  beforeAll,
  describe,
  expect,
  it
} from 'vitest';

/**
 * A file-explorer row, reduced to the collapse toggle.
 */
interface CollapsibleFileItem {
  collapsed?: boolean;
  setCollapsed?(this: void, isCollapsed: boolean): Promise<void>;
}

/**
 * The file-explorer view, reduced to its rows.
 */
interface FileExplorerView {
  fileItems: Record<string, CollapsibleFileItem>;
}

/**
 * `App`, reduced to the inline-title toggle that `obsidian-typings` does not
 * declare. Setting the config alone changes nothing on screen.
 */
interface InlineTitleApp {
  updateInlineTitleDisplay(this: void): void;
}

const WIDTH_IN_PIXELS = 1200;
const HEIGHT_IN_PIXELS = 800;

const PLUGIN_ID = 'obsidian-custom-attachment-location';

const NOTE_FOLDER = 'Meetings';
const SUBJECT_NOTE_NAME = 'Kickoff meeting';
const SUBJECT_NOTE_PATH = `${NOTE_FOLDER}/${SUBJECT_NOTE_NAME}.md`;
const SECOND_NOTE_PATH = `${NOTE_FOLDER}/Retrospective.md`;
const RENAMED_NOTE_NAME = 'Kickoff meeting 2026';
const RENAMED_NOTE_PATH = `${NOTE_FOLDER}/${RENAMED_NOTE_NAME}.md`;

/**
 * What a pasted screenshot is called before anything renames it — Obsidian's own
 * naming, and the name the README complains about.
 */
const PASTED_FILE_NAME = 'Pasted image 20260815093000';

/**
 * The pile shot 1 is about — Obsidian's naming, four days running.
 */
const PILE_FILE_NAMES = [
  'Pasted image 20260812101500',
  'Pasted image 20260813142200',
  'Pasted image 20260814090500',
  PASTED_FILE_NAME
];

const IMAGES_DIRECTORY = join(process.cwd(), 'images', 'screenshots');

beforeAll(async () => {
  const vault = getTemporaryVault();

  vault.populate({
    [`.obsidian/plugins/${PLUGIN_ID}/data.json`]: JSON.stringify({
      // The pattern the plugin's own defaults recommend, spelled out so the
      // Frames match what the settings would show.
      // eslint-disable-next-line no-template-curly-in-string -- A plugin token, not a template literal of this file.
      attachmentFolderPath: './assets/${noteFileName}',
      attachmentRenameMode: 'All',
      // eslint-disable-next-line no-template-curly-in-string -- Plugin tokens, not a template literal of this file.
      generatedAttachmentFileName: '${noteFileName}-${date:{momentJsFormat:\'YYYYMMDD\'}}',
      shouldHandleRenames: true,
      shouldRenameAttachmentFolder: true
    }),
    [SECOND_NOTE_PATH]: '# Retrospective\n\nWhat went well, what did not.\n',
    [SUBJECT_NOTE_PATH]: `# ${SUBJECT_NOTE_NAME}\n\nNotes from the kickoff.\n`
  });
  await vault.syncToDevice();

  await evalInObsidian({
    async callback({ app, lib: { waitUntil }, subjectNotePath }) {
      const SETTLE_TIMEOUT_IN_MILLISECONDS = 20_000;
      const SETTLE_DELAY_IN_MILLISECONDS = 1000;

      app.changeTheme('obsidian');

      await waitUntil({
        message: 'the staged notes to appear in the vault',
        predicate: () => Boolean(app.vault.getFileByPath(subjectNotePath)),
        timeoutInMilliseconds: SETTLE_TIMEOUT_IN_MILLISECONDS
      });

      // The file explorer IS the subject here — where a file landed is the whole
      // Story — so it stays open in every frame.
      app.workspace.leftSplit.expand();
      const fileExplorerLeaf = app.workspace.getLeavesOfType('file-explorer')[0];
      if (fileExplorerLeaf) {
        await app.workspace.revealLeaf(fileExplorerLeaf);
      }

      app.vault.setConfig('showInlineTitle', false);
      const inlineTitleApp: unknown = app;
      (inlineTitleApp as InlineTitleApp).updateInlineTitleDisplay();

      await sleep(SETTLE_DELAY_IN_MILLISECONDS);
    },
    input: { subjectNotePath: SUBJECT_NOTE_PATH },
    vaultPath: vaultPath()
  });
});

describe('desktop store screenshots', () => {
  it('1 - what Obsidian does on its own', async () => {
    await setPluginEnabled(false);

    // Four pastes, not one: the complaint is a PILE of identically-shaped names,
    // And a single file under the caption "one heap" would be the caption doing
    // The work the picture is supposed to do. Two notes, so the pile visibly
    // Belongs to no note in particular.
    const savedPaths: string[] = [];
    for (const [index, fileName] of PILE_FILE_NAMES.entries()) {
      const notePath = index % 2 === 0 ? SUBJECT_NOTE_PATH : SECOND_NOTE_PATH;
      savedPaths.push(await pasteAttachment(notePath, fileName));
    }

    // Obsidian's own default is the vault root, and the name is the timestamp
    // One. Both halves of the complaint, asserted rather than assumed.
    expect(savedPaths).toStrictEqual(PILE_FILE_NAMES.map((fileName) => `${fileName}.png`));
    await openNote(SUBJECT_NOTE_PATH);
    await shoot(1, 'Every pasted screenshot in one heap, named after the clock');
  });

  it('2 - a folder per note', async () => {
    await setPluginEnabled(true);
    const savedPath = await pasteAttachment(SUBJECT_NOTE_PATH, PASTED_FILE_NAME);
    expect(savedPath).toContain(`${NOTE_FOLDER}/assets/${SUBJECT_NOTE_NAME}/`);
    await openNote(SUBJECT_NOTE_PATH);
    await shoot(2, 'With the plugin: a folder of its own, beside the note');
  });

  it('3 - named after the note that owns it', async () => {
    const savedPath = await pasteAttachment(SECOND_NOTE_PATH, PASTED_FILE_NAME);
    expect(savedPath).toContain('Retrospective-');
    expect(savedPath).not.toContain(PASTED_FILE_NAME);
    await openNote(SECOND_NOTE_PATH);
    await shoot(3, 'And named after the note it belongs to, not the clock');
  });

  it('4 - the attachments follow a renamed note', async () => {
    const paths = await renameNote();
    expect(paths).toContain(`${NOTE_FOLDER}/assets/${RENAMED_NOTE_NAME}`);
    expect(paths).not.toContain(`${NOTE_FOLDER}/assets/${SUBJECT_NOTE_NAME}`);
    await openNote(RENAMED_NOTE_PATH);
    await shoot(4, 'Rename the note and its attachments move with it');
  });

  it('5 - the link inside the note still resolves', async () => {
    const embedCount = await openNote(RENAMED_NOTE_PATH, 'preview');
    expect(embedCount).toBeGreaterThan(0);
    await shoot(5, 'The embed still resolves — nothing is left pointing nowhere');
  });
});

/**
 * Builds the image every "paste" in this suite inserts.
 *
 * Big enough to be VISIBLE in a 1200x800 frame — an inline 2x2 pixel PNG renders
 * as a real embed and photographs as nothing at all — and flat enough to read as
 * a placeholder screenshot rather than compete with the file explorer beside it.
 *
 * @returns The PNG's bytes.
 */
async function buildScreenshotAttachment(): Promise<Uint8Array> {
  // Drawn as shapes rather than text: sharp renders SVG text through whatever
  // Fonts the host happens to have, so a captioned placeholder would look
  // Different on another machine — or lose its caption entirely.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="480" height="270">
    <rect width="480" height="270" rx="10" fill="#f4f5f8"/>
    <rect width="480" height="34" rx="10" fill="#5a76b4"/>
    <rect y="24" width="480" height="10" fill="#5a76b4"/>
    <circle cx="20" cy="17" r="5" fill="#f4f5f8" opacity="0.85"/>
    <circle cx="38" cy="17" r="5" fill="#f4f5f8" opacity="0.55"/>
    <circle cx="56" cy="17" r="5" fill="#f4f5f8" opacity="0.35"/>
    <rect x="24" y="64" width="300" height="14" rx="7" fill="#c3c9d6"/>
    <rect x="24" y="96" width="432" height="10" rx="5" fill="#d8dce5"/>
    <rect x="24" y="120" width="400" height="10" rx="5" fill="#d8dce5"/>
    <rect x="24" y="144" width="360" height="10" rx="5" fill="#d8dce5"/>
    <rect x="24" y="180" width="200" height="60" rx="8" fill="#e3e7ef"/>
    <rect x="244" y="180" width="212" height="60" rx="8" fill="#e3e7ef"/>
  </svg>`;

  return await sharp(Buffer.from(svg)).png().toBuffer();
}

/**
 * Opens the staged note in the given mode.
 *
 * @param notePath - Vault-relative path of the note.
 * @param mode - `source` for raw Markdown, `preview` for the rendered note.
 * @returns How many attachment embeds rendered.
 */
async function openNote(notePath: string, mode = 'source'): Promise<number> {
  return await evalInObsidian({
    async callback({ app, lib: { waitUntil }, mode: viewMode, notePath: path }) {
      const RENDER_TIMEOUT_IN_MILLISECONDS = 20_000;
      const SETTLE_DELAY_IN_MILLISECONDS = 1500;
      const RESIZE_SETTLE_DELAY_IN_MILLISECONDS = 2000;

      // Let the previous shot's capture settle: the device-metrics override it
      // Sets and clears disturbs anything driven too soon afterwards.
      await sleep(RESIZE_SETTLE_DELAY_IN_MILLISECONDS);

      const file = app.vault.getFileByPath(path);
      if (!file) {
        throw new Error(`Note is missing from the vault: ${path}`);
      }

      const leaf = app.workspace.getLeaf(false);
      await leaf.openFile(file);
      await leaf.setViewState({
        state: { file: path, mode: viewMode, source: viewMode === 'source' },
        type: 'markdown'
      });

      await waitUntil({
        message: 'the note to render',
        predicate: () => Boolean(document.querySelector('.cm-content, .markdown-preview-view')),
        timeoutInMilliseconds: RENDER_TIMEOUT_IN_MILLISECONDS
      });

      // A folder the tree has not expanded is a folder the reader cannot see, and
      // WHERE the attachment landed is the entire story here. Expanded on every
      // Shot rather than once, because each paste creates a new folder that
      // Arrives collapsed.
      const fileExplorerLeaf = app.workspace.getLeavesOfType('file-explorer')[0];
      if (fileExplorerLeaf) {
        const view: unknown = fileExplorerLeaf.view;
        for (const item of Object.values((view as FileExplorerView).fileItems)) {
          if (item.collapsed === true) {
            await item.setCollapsed?.(false);
          }
        }
      }

      await sleep(SETTLE_DELAY_IN_MILLISECONDS);

      // Only the on-screen copies count — Obsidian leaves the note's previous
      // Render in the document, detached and zero-sized.
      return [...document.querySelectorAll('.internal-embed img, .image-embed img')]
        .filter((element) => element.getBoundingClientRect().width > 0).length;
    },
    input: { mode, notePath },
    vaultPath: vaultPath()
  });
}

/**
 * Saves an attachment exactly the way a paste does, and embeds it in the note.
 *
 * `app.saveAttachment` is the sink Obsidian's own paste handler calls, and the
 * one the plugin patches, so the returned path is the plugin's answer — or
 * Obsidian's, when it is disabled — never something this suite chose. The note
 * has to be the ACTIVE file first: the plugin reads `getActiveFile()` to decide
 * both the folder and the name, and falls back to plain behavior without it.
 *
 * @param notePath - The note the attachment is pasted into.
 * @param fileName - The base name the clipboard image arrives under.
 * @returns The path the attachment was actually saved to.
 */
async function pasteAttachment(notePath: string, fileName: string): Promise<string> {
  await openNote(notePath);

  return await evalInObsidian({
    async callback({ app, fileName: baseName, notePath: path, pngBytes }) {
      const SETTLE_DELAY_IN_MILLISECONDS = 1200;

      const file = app.vault.getFileByPath(path);
      if (!file) {
        throw new Error(`Note is missing from the vault: ${path}`);
      }

      const binary = Uint8Array.from(pngBytes);

      const savedFile = await app.saveAttachment(baseName, 'png', binary.buffer);

      // `generateMarkdownLink` returns a plain link even for an image, so the `!`
      // Is added here — without it the note shows link TEXT and shot 5 has no
      // Embed to prove still resolves.
      const link = app.fileManager.generateMarkdownLink(savedFile, file.path);
      await app.vault.process(file, (content) => `${content}\n!${link}\n`);

      await sleep(SETTLE_DELAY_IN_MILLISECONDS);

      return savedFile.path;
    },
    input: { fileName, notePath, pngBytes: [...await buildScreenshotAttachment()] },
    vaultPath: vaultPath()
  });
}

/**
 * Renames the subject note through the Obsidian API, the way a user would.
 *
 * @returns Every folder path in the vault afterwards, so the shot can assert the
 * attachment folder followed the note.
 */
async function renameNote(): Promise<string[]> {
  return await evalInObsidian({
    async callback({ app, lib: { waitUntil }, renamedNotePath, subjectNotePath }) {
      const RENAME_TIMEOUT_IN_MILLISECONDS = 20_000;
      const SETTLE_DELAY_IN_MILLISECONDS = 1500;
      const RESIZE_SETTLE_DELAY_IN_MILLISECONDS = 2000;

      await sleep(RESIZE_SETTLE_DELAY_IN_MILLISECONDS);

      const file = app.vault.getFileByPath(subjectNotePath);
      if (!file) {
        throw new Error(`Note is missing from the vault: ${subjectNotePath}`);
      }

      await app.fileManager.renameFile(file, renamedNotePath);

      await waitUntil({
        message: 'the renamed note to settle',
        predicate: () => Boolean(app.vault.getFileByPath(renamedNotePath)),
        timeoutInMilliseconds: RENAME_TIMEOUT_IN_MILLISECONDS
      });

      await sleep(SETTLE_DELAY_IN_MILLISECONDS);

      return app.vault.getAllFolders().map((folder) => folder.path);
    },
    input: { renamedNotePath: RENAMED_NOTE_PATH, subjectNotePath: SUBJECT_NOTE_PATH },
    vaultPath: vaultPath()
  });
}

/**
 * Enables or disables the plugin, so shot 1 can show the unplugged vault.
 *
 * @param isEnabled - Whether the plugin should be on.
 */
async function setPluginEnabled(isEnabled: boolean): Promise<void> {
  await evalInObsidian({
    async callback({ app, isEnabled: shouldEnable, pluginId }) {
      const SETTLE_DELAY_IN_MILLISECONDS = 2000;

      if (shouldEnable) {
        await app.plugins.enablePlugin(pluginId);
      } else {
        await app.plugins.disablePlugin(pluginId);
      }

      await sleep(SETTLE_DELAY_IN_MILLISECONDS);
    },
    input: { isEnabled, pluginId: PLUGIN_ID },
    vaultPath: vaultPath()
  });
}

/**
 * Captures the window, captions it, and writes it as
 * `images/screenshots/screenshot-desktop-<index>.png`.
 *
 * @param index - The 1-based listing position.
 * @param caption - The caption drawn across the bottom of the frame.
 */
async function shoot(index: number, caption: string): Promise<void> {
  const bytes = await captureObsidianScreenshot({
    heightInPixels: HEIGHT_IN_PIXELS,
    vaultPath: vaultPath(),
    widthInPixels: WIDTH_IN_PIXELS
  });

  const labeled = await labelScreenshot(bytes, { text: caption });

  expect(readPngDimensions(labeled)).toStrictEqual({
    heightInPixels: HEIGHT_IN_PIXELS,
    widthInPixels: WIDTH_IN_PIXELS
  });

  mkdirSync(IMAGES_DIRECTORY, { recursive: true });
  writeFileSync(join(IMAGES_DIRECTORY, `screenshot-desktop-${String(index)}.png`), labeled);
}

function vaultPath(): string {
  return getTemporaryVault().path;
}
