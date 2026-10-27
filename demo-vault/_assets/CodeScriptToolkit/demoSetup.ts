import type {
  App,
  TFile
} from 'obsidian';

import {
  Notice,
  TFolder
} from 'obsidian';
import { configureCommunityPlugin } from '@mnaoumov/obsidian-lib/community-plugins';
import { findPluginApi } from '@mnaoumov/obsidian-lib/plugin/plugin-api';

// The `obsidian-` prefix is part of the id, not decoration: it is what `manifest.json` and the vault's
// `community-plugins.json` both say, so it is the folder every settings write has to land in.
const PLUGIN_ID = 'obsidian-custom-attachment-location';

// `Note priorities` moved to this plugin in 12.0.0, so a demo that ranks notes configures it there.
const ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID = 'advanced-rename-and-delete-handler';

// Two different 16x16 images, so a deduplicated pair and a different picture can be told apart by content.
const BLUE_IMAGE_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFklEQVR4nGOwbvpGEmIY1TCqYfhqAACHB7MQtEO1oAAAAABJRU5ErkJggg==';
const ORANGE_IMAGE_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFklEQVR4nGP4Oo+bJMQwqmFUw/DVAAACRZ4QdD+g5wAAAABJRU5ErkJggg==';

// The smallest file a PDF viewer accepts as one. The demos only need its name and extension.
const SAMPLE_PDF_TEXT = '%PDF-1.4\n%%EOF\n';

const COLLECT_MATERIALS_FOLDER_PATH = 'Materials/05 Collect attachments';
const LINK_DISPLAY_TEXT_FOLDER_PATH = 'Materials/07 Link display text';
const NAVIGATION_FOLDER_PATH = 'Materials/10 Navigation';

const NOTICE_DURATION_IN_MILLISECONDS = 15_000;
const WAIT_STEP_IN_MILLISECONDS = 100;
const WAIT_TIMEOUT_IN_MILLISECONDS = 5_000;

const ALPHA_BRAVO_TOKENS = `registerCustomToken('alpha', (ctx) => {
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  return ctx.noteFileName + ctx.app.appId + formatValue + ctx.obsidian.apiVersion;
});

registerCustomToken('bravo', async (ctx) => {
  await sleep(100);
  const formatValue = ctx.format?.formatKey ?? 'defaultFormatValue';
  return ctx.noteFileName + formatValue;
});
`;

const IMAGES_ONLY_TOKEN = `registerCustomToken('imagesOnly', async (ctx) => {
  const imageExtensions = ['avif', 'bmp', 'gif', 'jpeg', 'jpg', 'png', 'svg', 'webp'];
  if (!imageExtensions.includes(ctx.attachmentFileExtension.toLowerCase())) {
    return ctx.attachmentFileName;
  }

  return await ctx.fillTemplate('{{noteFileName}}-{{date:YYYYMMDDHHmmssSSS}}');
});
`;

/**
 * The part of this plugin's published API the demos call. The whole of it is declared in `api.d.ts`.
 */
interface CustomAttachmentLocationDemoApi {
  collectAttachments(params: { readonly pathsOrFiles: readonly string[] }): Promise<void>;
  getAvailablePathForAttachments(params: {
    readonly attachmentFileBaseName: string;
    readonly attachmentFileExtension: string;
    readonly context: 'Unknown';
    readonly notePathOrFile: TFile;
    readonly oldAttachmentPathOrFile: string;
    readonly readAttachmentFileContent: () => Promise<ArrayBuffer>;
    readonly shouldSkipMissingAttachmentFolderCreation: boolean;
  }): Promise<string>;
}

/**
 * The collect demos in `05 Collect attachments`, one per `Try it` section.
 */
export type CollectDemoId = 'basic' | 'dedupe' | 'destination' | 'extensions' | 'priorities' | 'rawPath' | 'unitFolder';

interface CollectDemo {
  /**
   * The files the demo starts from, by path inside its folder.
   */
  readonly files: Readonly<Record<string, ArrayBuffer | string>>;

  /**
   * The folder the demo owns, from the vault root. Its set-up deletes and recreates it.
   */
  readonly folderPath: string;

  /**
   * The note the reader opens first, inside the folder.
   */
  readonly notePath: string;

  /**
   * The settings the demo starts from: everything its outcome depends on, so a setting another demo left
   * changed does not change this one.
   */
  readonly settings: DemoSettingsPatch;
}

interface CollectDemoReport {
  /**
   * Every file now in the demo's folder, relative to it, sorted.
   */
  readonly files: string[];
}

interface DemoSettingsPatch {
  attachmentFolderPath?: string;
  attachmentRenameMode?: 'All' | 'None' | 'Only pasted images';
  attachmentUnitFolderPaths?: string[];
  collectAttachmentUsedByMultipleNotesMode?: 'Cancel' | 'Copy' | 'Move' | 'Prompt' | 'Skip';
  collectedAttachmentFolderPath?: string;
  customTokensStr?: string;
  excludeExtensionsFromMultipleNotesCheck?: string[];
  generatedAttachmentFileName?: string;
  sidecarExtensions?: string[];
  insertedLinkText?: string;
  shouldDeduplicateIdenticalAttachments?: boolean;
  shouldFollowObsidianAttachmentLocation?: boolean;
  shouldRenameAttachmentFiles?: boolean;
  shouldRenameCollectedAttachments?: boolean;
  shouldSetLinkDisplayTextToAttachmentFileName?: boolean;
  shouldSkipCollectingAttachmentsReferencedByRawPath?: boolean;
}

interface LinkDisplayTextDemoReport {
  /**
   * The link Obsidian generated to the PDF.
   */
  readonly attachmentLink: string;

  /**
   * The link Obsidian generated to the other note.
   */
  readonly noteLink: string;
}

interface SaveSampleAttachmentParams {
  /**
   * What to save: an image, which the default `Only pasted images` mode renames, or a PDF.
   */
  readonly kind: 'image' | 'pdf';
}

interface TieDemoReport {
  /**
   * The notes the shared-attachment dialog lists.
   */
  readonly listedNotes: string[];
}

const COLLECT_SETTINGS_BASELINE: DemoSettingsPatch = {
  attachmentFolderPath: './assets/{{noteFileName}}',
  attachmentUnitFolderPaths: [],
  collectAttachmentUsedByMultipleNotesMode: 'Skip',
  collectedAttachmentFolderPath: '',
  excludeExtensionsFromMultipleNotesCheck: [],
  shouldDeduplicateIdenticalAttachments: false,
  shouldFollowObsidianAttachmentLocation: false,
  shouldRenameCollectedAttachments: false,
  shouldSkipCollectingAttachmentsReferencedByRawPath: false
};

const COLLECT_DEMOS: Readonly<Record<CollectDemoId, CollectDemo>> = {
  basic: {
    files: {
      'Collect demo.md': `![[${COLLECT_MATERIALS_FOLDER_PATH}/Collect demo/loose/image.png]]\n`,
      'loose/image.png': decodeBase64(BLUE_IMAGE_BASE64)
    },
    folderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Collect demo`,
    notePath: 'Collect demo.md',
    settings: COLLECT_SETTINGS_BASELINE
  },
  dedupe: {
    files: {
      'a/image.png': decodeBase64(BLUE_IMAGE_BASE64),
      'a/Note A.md': `![[${COLLECT_MATERIALS_FOLDER_PATH}/Dedupe demo/a/image.png]]\n`,
      'b/image.png': decodeBase64(BLUE_IMAGE_BASE64),
      'b/Note B.md': `![[${COLLECT_MATERIALS_FOLDER_PATH}/Dedupe demo/b/image.png]]\n`
    },
    folderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Dedupe demo`,
    notePath: 'a/Note A.md',
    settings: {
      ...COLLECT_SETTINGS_BASELINE,
      attachmentFolderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Dedupe demo/_Attachments`
    }
  },
  destination: {
    files: {
      '_Attachments/image.png': decodeBase64(BLUE_IMAGE_BASE64),
      'Example Note.md': `![[${COLLECT_MATERIALS_FOLDER_PATH}/Destination demo/_Attachments/image.png]]\n`
    },
    folderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Destination demo`,
    notePath: 'Example Note.md',
    settings: {
      ...COLLECT_SETTINGS_BASELINE,
      attachmentFolderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Destination demo/_Attachments`
    }
  },
  extensions: {
    files: {
      'Note A.md': `[[${COLLECT_MATERIALS_FOLDER_PATH}/Shared type demo/shared.af]]\n\n![[${COLLECT_MATERIALS_FOLDER_PATH}/Shared type demo/shared.png]]\n`,
      'Note B.md': `[[${COLLECT_MATERIALS_FOLDER_PATH}/Shared type demo/shared.af]]\n\n![[${COLLECT_MATERIALS_FOLDER_PATH}/Shared type demo/shared.png]]\n`,
      'shared.af': 'A file type shared between notes on purpose.\n',
      'shared.png': decodeBase64(BLUE_IMAGE_BASE64)
    },
    folderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Shared type demo`,
    notePath: 'Note A.md',
    settings: COLLECT_SETTINGS_BASELINE
  },
  priorities: {
    files: {
      'Drawing.excalidraw.md': `![[${COLLECT_MATERIALS_FOLDER_PATH}/Note priorities demo/shared.png]]\n`,
      'Note.md': `![[${COLLECT_MATERIALS_FOLDER_PATH}/Note priorities demo/shared.png]]\n`,
      'shared.png': decodeBase64(BLUE_IMAGE_BASE64)
    },
    folderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Note priorities demo`,
    notePath: 'Note.md',
    settings: COLLECT_SETTINGS_BASELINE
  },
  rawPath: {
    files: {
      'Embed.md': '![[raw-demo.png]]\n',
      'raw-demo.png': decodeBase64(BLUE_IMAGE_BASE64),
      'raw-ref.md': '<img src="raw-demo.png">\n'
    },
    folderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Raw path demo`,
    notePath: 'Embed.md',
    settings: COLLECT_SETTINGS_BASELINE
  },
  unitFolder: {
    files: {
      'Saved page.md': `![[${COLLECT_MATERIALS_FOLDER_PATH}/Unit folder demo/saved-page/page_files/logo.png]]\n`,
      'saved-page/page_files/logo.png': decodeBase64(BLUE_IMAGE_BASE64),
      'saved-page/page_files/style.css': 'img { border: 1px solid; }\n'
    },
    folderPath: `${COLLECT_MATERIALS_FOLDER_PATH}/Unit folder demo`,
    notePath: 'Saved page.md',
    settings: COLLECT_SETTINGS_BASELINE
  }
};

/**
 * Reports where an attachment pasted into the ACTIVE note would be saved, right now, with the current
 * settings — folder and generated file name both.
 *
 * Pasting cannot be automated — the image has to come from your clipboard — but the answer the plugin
 * would give can be asked for directly, through the same resolver a paste goes through. So a token pattern
 * can be inspected without finding an image first, and without waiting to see where the file ends up.
 *
 * Manual equivalent: paste an image into the note and look at where it landed in the File Explorer.
 *
 * @returns The path, or `null` when no note is open.
 */
export async function previewAttachmentPath(app: App): Promise<null | string> {
  const activeFile = app.workspace.getActiveFile();
  if (!activeFile) {
    new Notice('Open a note first — the path depends on which note you are in.');
    return null;
  }

  const path = await resolveAttachmentPath({ app, kind: 'image', notePath: activeFile.path, shouldCreateFolder: false });
  new Notice(`A pasted image would be saved as:\n${path}`, NOTICE_DURATION_IN_MILLISECONDS);
  return path;
}

/**
 * Saves a sample file as an attachment of the ACTIVE note, under the folder and the name a paste (for the
 * image) or a drop (for the PDF) would give it with the current settings.
 *
 * Manual equivalent: paste an image, or drag a PDF, into the note.
 *
 * @returns The saved file's path, or `null` when no note is open.
 */
export async function saveSampleAttachment(app: App, params: SaveSampleAttachmentParams): Promise<null | string> {
  const activeFile = app.workspace.getActiveFile();
  if (!activeFile) {
    new Notice('Open a note first — the attachment belongs to the note you are in.');
    return null;
  }

  const path = await resolveAttachmentPath({ app, kind: params.kind, notePath: activeFile.path, shouldCreateFolder: true });
  await app.vault.createBinary(path, sampleContent(params.kind));
  new Notice(`Saved a sample ${params.kind === 'image' ? 'image' : 'PDF'} as:\n${path}`, NOTICE_DURATION_IN_MILLISECONDS);
  return path;
}

/**
 * Applies a settings patch, live, through the plugin's own settings component.
 *
 * Manual equivalent: edit the same field in **Settings -> Community plugins ->
 * `Custom Attachment Location`**.
 */
export async function changeSettings(app: App, patch: DemoSettingsPatch): Promise<void> {
  await configureCommunityPlugin({ app, pluginId: PLUGIN_ID, settings: patch });
  new Notice('Applied. Ask where a paste would go to see the effect.');
}

/**
 * Sets **Note priorities**, which `Advanced Rename and Delete Handler` owns.
 *
 * Manual equivalent: edit **Note priorities** in **Settings -> Community plugins ->
 * `Advanced Rename and Delete Handler`**, one entry per line.
 */
export async function changeNotePriorities(app: App, notePriorities: string[]): Promise<void> {
  await configureCommunityPlugin({ app, pluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID, settings: { notePriorities } });
  new Notice(notePriorities.length === 0 ? 'Note priorities cleared.' : `Note priorities: ${notePriorities.join(', ')}`);
}

/**
 * Restores the two patterns this vault ships with, and puts the plugin back in charge of the folder.
 *
 * Manual equivalent: turn **Follow Obsidian attachment location** off, set **Location for new attachments**
 * back to `./assets/{{noteFileName}}` and the generated file name back to its default.
 */
export async function restoreDefaultPatterns(app: App): Promise<void> {
  await changeSettings(app, {
    attachmentFolderPath: './assets/{{noteFileName}}',
    generatedAttachmentFileName: 'file-{{date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}}',
    shouldFollowObsidianAttachmentLocation: false
  });
}

/**
 * Restores every setting the collect demos change, and clears **Note priorities**.
 *
 * Manual equivalent: put each setting named in `05 Collect attachments` back to the value this vault ships
 * with — all of them empty or off, the mode `Skip`, the location `./assets/{{noteFileName}}`.
 */
export async function restoreCollectSettings(app: App): Promise<void> {
  await configureCommunityPlugin({ app, pluginId: PLUGIN_ID, settings: COLLECT_SETTINGS_BASELINE });
  await configureCommunityPlugin({ app, pluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID, settings: { notePriorities: [] } });
  new Notice('The collect settings are back to this vault\'s defaults.');
}

/**
 * Registers the `alpha` and `bravo` example tokens from `04 Custom tokens`, replacing any custom tokens.
 *
 * Manual equivalent: paste the example into **Custom tokens** in **Settings -> Community plugins ->
 * `Custom Attachment Location`**.
 */
export async function registerExampleTokens(app: App): Promise<void> {
  await applyCustomTokens(app, ALPHA_BRAVO_TOKENS);
  await changeSettings(app, { generatedAttachmentFileName: '{{alpha}}' });
}

/**
 * Registers the `imagesOnly` token from `04 Custom tokens` and turns on everything its worked example needs.
 *
 * Manual equivalent: paste the token into **Custom tokens**, set **Attachment rename mode** to `All` and
 * **Generated attachment file name** to `{{imagesOnly}}`.
 */
export async function registerImagesOnlyToken(app: App): Promise<void> {
  await applyCustomTokens(app, IMAGES_ONLY_TOKEN);
  await changeSettings(app, { attachmentRenameMode: 'All', generatedAttachmentFileName: '{{imagesOnly}}' });
}

/**
 * Removes the example tokens and puts the naming settings they changed back.
 *
 * Manual equivalent: empty **Custom tokens**, set **Attachment rename mode** back to `Only pasted images` and
 * the generated file name back to its default.
 */
export async function removeExampleTokens(app: App): Promise<void> {
  await changeSettings(app, {
    attachmentRenameMode: 'Only pasted images',
    customTokensStr: '',
    generatedAttachmentFileName: 'file-{{date:{momentJsFormat:\'YYYYMMDDHHmmssSSS\'}}}'
  });
}

/**
 * Creates a collect demo from scratch: deletes its folder, writes its files, applies the settings it starts
 * from, optionally changed, and opens its first note.
 *
 * Manual equivalent: create the files the note's `Try it` lists and set each setting by hand.
 *
 * @returns What the demo's folder holds.
 */
export async function setUpCollectDemo(app: App, demoId: CollectDemoId, settings: DemoSettingsPatch = {}): Promise<CollectDemoReport> {
  const demo = COLLECT_DEMOS[demoId];
  await recreateFolder(app, demo.folderPath, demo.files);
  await configureCommunityPlugin({ app, pluginId: PLUGIN_ID, settings: { ...demo.settings, ...settings } });
  await configureCommunityPlugin({ app, pluginId: ADVANCED_RENAME_AND_DELETE_HANDLER_PLUGIN_ID, settings: { notePriorities: [] } });
  await openFile(app, `${demo.folderPath}/${demo.notePath}`);
  return reportFolder(app, demo.folderPath, 'Set up. The demo folder holds');
}

/**
 * Runs **Collect attachments in current note** on the given notes of a demo, one after another.
 *
 * Manual equivalent: open each note and run **Collect attachments in current note** from the Command Palette.
 *
 * @param notePaths - The notes, inside the demo's folder. The demo's first note when left out.
 * @returns What the demo's folder holds afterwards.
 */
export async function collectInDemo(app: App, demoId: CollectDemoId, notePaths?: string[]): Promise<CollectDemoReport> {
  const demo = COLLECT_DEMOS[demoId];
  const api = getApi();
  for (const notePath of notePaths ?? [demo.notePath]) {
    await api.collectAttachments({ pathsOrFiles: [`${demo.folderPath}/${notePath}`] });
  }
  return reportFolder(app, demo.folderPath, 'Collected. The demo folder now holds');
}

/**
 * Saves a sample image into the destination demo's note the way a paste would.
 *
 * Manual equivalent: paste an image into `Example Note`.
 *
 * @returns What the demo's folder holds afterwards.
 */
export async function pasteIntoDestinationDemo(app: App): Promise<CollectDemoReport> {
  const demo = COLLECT_DEMOS.destination;
  await openFile(app, `${demo.folderPath}/${demo.notePath}`);
  await saveSampleAttachment(app, { kind: 'image' });
  return reportFolder(app, demo.folderPath, 'Pasted. The demo folder now holds');
}

/**
 * Adds a second markdown note to the priorities demo, so two notes tie, sets the shared-attachment mode to
 * `Prompt`, and collects from the first note. The dialog it opens is left open for you to read.
 *
 * Manual equivalent: embed `shared.png` in a new note beside `Note`, set **Collect attachment used by multiple
 * notes mode** to `Prompt`, and run **Collect attachments in current note** in `Note`.
 *
 * @returns The notes the dialog lists.
 */
export async function collectPrioritiesTie(app: App): Promise<TieDemoReport> {
  const demo = COLLECT_DEMOS.priorities;
  const secondNotePath = `${demo.folderPath}/Note 2.md`;
  if (!app.vault.getFileByPath(secondNotePath)) {
    // The earlier steps may have moved the image into `Note`'s folder, so embed it wherever it is now.
    const imageFile = app.metadataCache.getFirstLinkpathDest('shared.png', `${demo.folderPath}/${demo.notePath}`);
    await app.vault.create(secondNotePath, `![[${imageFile?.path ?? `${demo.folderPath}/shared.png`}]]\n`);
  }
  await configureCommunityPlugin({ app, pluginId: PLUGIN_ID, settings: { collectAttachmentUsedByMultipleNotesMode: 'Prompt' } });

  // Not awaited: the collect waits for the dialog, which is yours to answer.
  void getApi().collectAttachments({ pathsOrFiles: [`${demo.folderPath}/${demo.notePath}`] });

  const list = await waitFor(() => document.querySelector('.custom-attachment-location-multiple-notes-list'));
  const listedNotes = list ? Array.from(list.querySelectorAll('li'), (li) => li.textContent?.trim() ?? '') : [];
  return { listedNotes };
}

/**
 * Creates the link-display-text demo from scratch and writes into its note the links Obsidian generates to a
 * PDF and to another note — the same call a drop or a link suggestion makes.
 *
 * Manual equivalent: drag a PDF into a note, then insert a link to another note with `[[`.
 *
 * @returns The two links.
 */
export async function insertLinksForDisplayTextDemo(app: App): Promise<LinkDisplayTextDemoReport> {
  const notePath = `${LINK_DISPLAY_TEXT_FOLDER_PATH}/Link display demo.md`;
  await recreateFolder(app, LINK_DISPLAY_TEXT_FOLDER_PATH, {
    'Link display demo.md': '',
    'Other note.md': 'Another note.\n',
    'report-2026.pdf': SAMPLE_PDF_TEXT
  });

  const attachmentLink = app.fileManager.generateMarkdownLink(getFile(app, `${LINK_DISPLAY_TEXT_FOLDER_PATH}/report-2026.pdf`), notePath);
  const noteLink = app.fileManager.generateMarkdownLink(getFile(app, `${LINK_DISPLAY_TEXT_FOLDER_PATH}/Other note.md`), notePath);
  await app.vault.modify(getFile(app, notePath), `- PDF: ${attachmentLink}\n- Note: ${noteLink}\n`);
  await openFile(app, notePath);
  new Notice(`The PDF link: ${attachmentLink}\nThe note link: ${noteLink}`, NOTICE_DURATION_IN_MILLISECONDS);
  return { attachmentLink, noteLink };
}

/**
 * Saves and links a renamed PDF, keeping its arrival name as display text when enabled.
 *
 * @param app - The demo vault app.
 * @param shouldEnable - Whether to use the original-name link template.
 * @returns The inserted link.
 */
export async function insertOriginalNameLinkDemo(app: App, shouldEnable: boolean): Promise<string> {
  const folderPath = `${LINK_DISPLAY_TEXT_FOLDER_PATH}/Original name`;
  const notePath = `${folderPath}/Original name demo.md`;
  await recreateFolder(app, folderPath, { 'Original name demo.md': '' });
  await changeSettings(app, {
    attachmentFolderPath: `${folderPath}/assets`,
    attachmentRenameMode: 'All',
    generatedAttachmentFileName: 'renamed-report',
    insertedLinkText: shouldEnable ? '{{originalAttachmentFileName}}' : '',
    shouldFollowObsidianAttachmentLocation: false,
    shouldSetLinkDisplayTextToAttachmentFileName: false
  });
  await openFile(app, notePath);
  const path = await resolveAttachmentPath({ app, kind: 'pdf', notePath, shouldCreateFolder: true });
  const attachment = await app.vault.createBinary(path, sampleContent('pdf'));
  const link = app.fileManager.generateMarkdownLink(attachment, notePath);
  await app.vault.modify(getFile(app, notePath), `${link}\n`);
  await openFile(app, notePath);
  new Notice(`Inserted: ${link}`, NOTICE_DURATION_IN_MILLISECONDS);
  return link;
}

/**
 * Imports a document and a companion under one random name, with the companion first.
 *
 * Manual equivalent: drop document.html and document.html.p7s into a note together with attachment renaming on.
 * The companion contains demonstration text, not a cryptographic signature.
 *
 * @param app - The demo vault app.
 * @returns The two paths, in import order.
 */
export async function saveSidecarDemo(app: App): Promise<string[]> {
  const folderPath = 'Materials/02 Attachment file naming/Sidecars';
  const notePath = `${folderPath}/Sidecar demo.md`;
  await recreateFolder(app, folderPath, { 'Sidecar demo.md': '' });
  await changeSettings(app, {
    attachmentFolderPath: `${folderPath}/assets`,
    attachmentRenameMode: 'All',
    generatedAttachmentFileName: '{{random}}',
    shouldFollowObsidianAttachmentLocation: false,
    sidecarExtensions: ['p7s', 'sig', 'asc', 'srt', 'vtt']
  });
  await openFile(app, notePath);
  const files = await app.importAttachments([
    { name: 'document.html', extension: 'p7s', data: Promise.resolve(new TextEncoder().encode('Demonstration companion, not a real signature.').buffer) },
    { name: 'document', extension: 'html', data: Promise.resolve(new TextEncoder().encode('<html>Demonstration document</html>').buffer) }
  ], null);
  await app.vault.modify(getFile(app, notePath), files.map((file) => app.fileManager.generateMarkdownLink(file, notePath)).join('\n'));
  await openFile(app, notePath);
  new Notice('The HTML and its companion share one random name. Rename the HTML to see the companion follow.', NOTICE_DURATION_IN_MILLISECONDS);
  return files.map((file) => file.path);
}

/**
 * Creates the navigation demo from scratch: a note, and an image saved in that note's attachment folder under
 * this vault's default patterns, which it also restores.
 *
 * Manual equivalent: paste an image into a note.
 *
 * @returns The note's path.
 */
export async function setUpNavigationDemo(app: App): Promise<string> {
  await restoreDefaultPatterns(app);
  const notePath = `${NAVIGATION_FOLDER_PATH}/Navigation demo.md`;
  await recreateFolder(app, NAVIGATION_FOLDER_PATH, {
    'assets/Navigation demo/image.png': decodeBase64(BLUE_IMAGE_BASE64),
    'Navigation demo.md': `![[${NAVIGATION_FOLDER_PATH}/assets/Navigation demo/image.png]]\n`
  });
  await openFile(app, notePath);
  return notePath;
}

/**
 * Opens the navigation demo's note and runs **Go to attachment folder** on it.
 *
 * Manual equivalent: open `Navigation demo` and run **`Custom Attachment Location`: Go to attachment folder**.
 */
export async function goToNavigationDemoAttachmentFolder(app: App): Promise<void> {
  await openFile(app, `${NAVIGATION_FOLDER_PATH}/Navigation demo.md`);
  runCommand(app, 'go-to-attachment-folder');
}

/**
 * Opens the navigation demo's image and runs **Go to owning note** on it.
 *
 * Manual equivalent: click the image in the File Explorer, then run **`Custom Attachment Location`: Go to
 * owning note**.
 *
 * @returns The note it opened, or `null` when none opened.
 */
export async function goToNavigationDemoOwningNote(app: App): Promise<null | string> {
  const imagePath = `${NAVIGATION_FOLDER_PATH}/assets/Navigation demo/image.png`;
  await openFile(app, imagePath);
  runCommand(app, 'go-to-owning-note');
  const ownerFile = await waitFor(() => {
    const activeFile = app.workspace.getActiveFile();
    return activeFile && activeFile.path !== imagePath ? activeFile : null;
  });
  return ownerFile?.path ?? null;
}

/**
 * Saves custom tokens. Saving them registers them, so a pattern naming one is accepted straight after.
 */
async function applyCustomTokens(app: App, customTokensStr: string): Promise<void> {
  await configureCommunityPlugin({ app, pluginId: PLUGIN_ID, settings: { customTokensStr } });
}

function decodeBase64(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function findApi(): CustomAttachmentLocationDemoApi | null {
  return findPluginApi<CustomAttachmentLocationDemoApi>({ apiVersionRange: '^1.3.0', pluginId: PLUGIN_ID });
}

function getApi(): CustomAttachmentLocationDemoApi {
  const api = findApi();
  if (!api) {
    throw new Error('`Custom Attachment Location` is not running. Enable it, and `Advanced Rename and Delete Handler` with it.');
  }
  return api;
}

function getFile(app: App, path: string): TFile {
  const file = app.vault.getFileByPath(path);
  if (!file) {
    throw new Error(`The demo file ${path} is missing.`);
  }
  return file;
}

function listFiles(folder: TFolder, prefix: string, paths: string[]): void {
  for (const child of folder.children) {
    if (child instanceof TFolder) {
      listFiles(child, `${prefix}${child.name}/`, paths);
    } else {
      paths.push(`${prefix}${child.name}`);
    }
  }
}

async function openFile(app: App, path: string): Promise<void> {
  await app.workspace.getLeaf(false).openFile(getFile(app, path));
}

async function recreateFolder(app: App, folderPath: string, files: Readonly<Record<string, ArrayBuffer | string>>): Promise<void> {
  const existingFolder = app.vault.getFolderByPath(folderPath);
  if (existingFolder) {
    await app.vault.delete(existingFolder, true);
  }

  for (const [relativePath, content] of Object.entries(files)) {
    const path = `${folderPath}/${relativePath}`;
    const parentPath = path.slice(0, path.lastIndexOf('/'));
    if (!app.vault.getFolderByPath(parentPath)) {
      await app.vault.createFolder(parentPath);
    }
    if (typeof content === 'string') {
      await app.vault.create(path, content);
    } else {
      await app.vault.createBinary(path, content);
    }
  }
}

function reportFolder(app: App, folderPath: string, message: string): CollectDemoReport {
  const files: string[] = [];
  const folder = app.vault.getFolderByPath(folderPath);
  if (folder) {
    listFiles(folder, '', files);
  }
  files.sort((a, b) => a.localeCompare(b));
  new Notice(`${message}:\n${files.join('\n')}`, NOTICE_DURATION_IN_MILLISECONDS);
  return { files };
}

async function resolveAttachmentPath(params: { app: App; kind: SaveSampleAttachmentParams['kind']; notePath: string; shouldCreateFolder: boolean }): Promise<string> {
  const [attachmentFileBaseName, attachmentFileExtension] = params.kind === 'image' ? ['Pasted image', 'png'] : ['report-2026', 'pdf'];
  return await getApi().getAvailablePathForAttachments({
    attachmentFileBaseName,
    attachmentFileExtension,
    context: 'Unknown',
    notePathOrFile: getFile(params.app, params.notePath),
    oldAttachmentPathOrFile: `${attachmentFileBaseName}.${attachmentFileExtension}`,
    readAttachmentFileContent: () => Promise.resolve(sampleContent(params.kind)),
    shouldSkipMissingAttachmentFolderCreation: !params.shouldCreateFolder
  });
}

function runCommand(app: App, commandName: string): void {
  const commandId = `${PLUGIN_ID}:${commandName}`;
  if (!app.commands.executeCommandById(commandId)) {
    throw new Error(`The command ${commandId} is not available for the open file.`);
  }
}

function sampleContent(kind: SaveSampleAttachmentParams['kind']): ArrayBuffer {
  return kind === 'image' ? decodeBase64(ORANGE_IMAGE_BASE64) : new TextEncoder().encode(SAMPLE_PDF_TEXT).buffer;
}

async function waitFor<T>(probe: () => null | T): Promise<null | T> {
  const deadline = Date.now() + WAIT_TIMEOUT_IN_MILLISECONDS;
  while (Date.now() < deadline) {
    const value = probe();
    if (value) {
      return value;
    }
    await sleep(WAIT_STEP_IN_MILLISECONDS);
  }
  return null;
}
