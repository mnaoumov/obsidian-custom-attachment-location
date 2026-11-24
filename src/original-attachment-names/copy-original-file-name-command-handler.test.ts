import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type {
  Editor,
  App as ObsidianApp,
  TFile
} from 'obsidian';

import { initI18N } from '@mnaoumov/obsidian-lib/i18n/i18n';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import { App } from 'obsidian-test-mocks/obsidian';
import {
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { OriginalAttachmentNamesComponent } from './original-attachment-names-component.ts';

import { translationsMap } from '../i18n/locales/translations-map.ts';
import { CopyOriginalFileNameCommandHandler } from './copy-original-file-name-command-handler.ts';
import { copyOriginalFileName } from './original-file-name-modal.ts';

vi.mock('./original-file-name-modal.ts', () => ({
  copyOriginalFileName: vi.fn().mockResolvedValue(undefined)
}));

const mockedCopyOriginalFileName = vi.mocked(copyOriginalFileName);

const NOTE_EXTENSIONS = new Set(['base', 'canvas', 'md']);

interface Scenario {
  readonly checkCallback: (this: void, isChecking: boolean) => boolean;
  readonly pluginNoticeComponent: PluginNoticeComponent;
}

interface ScenarioParams {
  readonly activePath: null | string;
  readonly cursorLine?: string;
  readonly storedNames?: Readonly<Record<string, string>>;
}

beforeAll(async () => {
  await initI18N(translationsMap);
});

afterEach(() => {
  mockedCopyOriginalFileName.mockClear();
});

async function createScenario(params: ScenarioParams): Promise<Scenario> {
  const mockApp = App.createConfigured__().asOriginalType__();
  for (const path of ['note.md', 'other.md', 'drawing.canvas', 'table.base', 'image.png', 'unnamed.pdf']) {
    await mockApp.vault.create(path, '');
  }
  const activeFile = params.activePath === null ? null : mockApp.vault.getFileByPath(params.activePath);
  const cursorLine = params.cursorLine;
  const editor = cursorLine === undefined
    ? null
    : strictProxy<Editor>({
      getCursor: () => ({ ch: 0, line: 0 }),
      getLine: () => cursorLine,
      lineCount: () => 1
    });
  const app = strictProxy<ObsidianApp>({
    metadataCache: mockApp.metadataCache,
    vault: mockApp.vault,
    workspace: strictProxy<ObsidianApp['workspace']>({
      activeEditor: editor && activeFile ? { editor, file: activeFile } : null,
      getActiveFile: () => activeFile
    })
  });
  const storedNames = params.storedNames ?? { 'image.png': 'Screenshot 2026-11-23.png' };
  const pluginNoticeComponent = strictProxy<PluginNoticeComponent>({});
  const handler = new CopyOriginalFileNameCommandHandler({
    app,
    originalAttachmentNamesComponent: strictProxy<OriginalAttachmentNamesComponent>({ get: (path) => storedNames[path] ?? null }),
    pluginNoticeComponent,
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({
      isNoteEx: (candidate) => typeof candidate === 'object' && candidate !== null && NOTE_EXTENSIONS.has((candidate as TFile).extension)
    })
  });
  const command = handler.buildCommand();
  return {
    checkCallback: (isChecking) => command.checkCallback?.(isChecking) === true,
    pluginNoticeComponent
  };
}

describe('Copy original file name command', () => {
  it('should copy the stored name of the open attachment', async () => {
    const { checkCallback, pluginNoticeComponent } = await createScenario({ activePath: 'image.png' });
    expect(checkCallback(true)).toBe(true);
    checkCallback(false);
    await vi.waitFor(() => {
      expect(mockedCopyOriginalFileName).toHaveBeenCalledWith({ originalFileName: 'Screenshot 2026-11-23.png', pluginNoticeComponent });
    });
  });

  it.each(['note.md', 'drawing.canvas', 'table.base'])('should be unavailable while the note %s is open with no link under the cursor', async (activePath) => {
    const { checkCallback } = await createScenario({ activePath, cursorLine: 'plain text' });
    expect(checkCallback(true)).toBe(false);
  });

  it('should be unavailable with no open file', async () => {
    const { checkCallback } = await createScenario({ activePath: null });
    expect(checkCallback(true)).toBe(false);
  });

  it.each(['![[image.png]]', '[[image.png|alias]]', '[alias](image.png)', '![](image.png)'])('should copy the stored name of the attachment the link %s under the cursor resolves to', async (cursorLine) => {
    const { checkCallback, pluginNoticeComponent } = await createScenario({ activePath: 'note.md', cursorLine });
    expect(checkCallback(true)).toBe(true);
    checkCallback(false);
    await vi.waitFor(() => {
      expect(mockedCopyOriginalFileName).toHaveBeenCalledWith({ originalFileName: 'Screenshot 2026-11-23.png', pluginNoticeComponent });
    });
  });

  it.each(['[[other]]', '[[drawing.canvas]]', '[[missing.png]]', '[site](https://example.com/image.png)'])('should be unavailable when the link %s under the cursor resolves to no attachment', async (cursorLine) => {
    const { checkCallback } = await createScenario({ activePath: 'note.md', cursorLine });
    expect(checkCallback(true)).toBe(false);
  });

  it.each([
    ['open', 'unnamed.pdf', undefined],
    ['linked', 'note.md', '![[unnamed.pdf]]'],
    ['open with an empty stored name', 'image.png', undefined]
  ])('should be unavailable for an %s attachment with no stored name', async (_, activePath, cursorLine) => {
    const { checkCallback } = await createScenario({
      activePath,
      ...(cursorLine !== undefined && { cursorLine }),
      storedNames: { 'image.png': '' }
    });
    expect(checkCallback(true)).toBe(false);
    expect(mockedCopyOriginalFileName).not.toHaveBeenCalled();
  });
});
