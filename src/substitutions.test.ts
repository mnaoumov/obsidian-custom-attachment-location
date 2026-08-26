import type {
  App,
  EditorPosition
} from 'obsidian';
import type { StrictProxyPartial } from 'obsidian-dev-utils/strict-proxy';
import type { MockInstance } from 'vitest';

import { printError } from 'obsidian-dev-utils/error';
import { castTo } from 'obsidian-dev-utils/object-utils';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from './plugin-settings-component.ts';
import type { TokenValidator } from './token-validator.ts';

import { Substitutions } from './substitutions.ts';
import {
  ActionContext,
  TemplatePart
} from './token-evaluator-context.ts';

vi.mock('obsidian-dev-utils/error', () => ({
  printError: vi.fn<(error: unknown) => void>()
}));

interface ActiveEditorOverrides {
  cursor?: EditorPosition;
  filePath?: string;
}

interface SubstitutionsOverrides {
  activeEditorOverrides?: ActiveEditorOverrides;
  attachmentFileContent?: ArrayBuffer;
  cursorLine?: number;
  noteFilePath?: string;
  readAttachmentFileContent?(): Promise<ArrayBuffer>;
}

const mockPrintError = vi.mocked(printError);

const DOLLAR = '$';
const OPEN_BRACE = '{';
const CLOSE_BRACE = '}';

function createApp(activeEditorOverrides?: ActiveEditorOverrides): App {
  const cursor = activeEditorOverrides?.cursor;
  const filePath = activeEditorOverrides?.filePath;
  const editor: StrictProxyPartial<NonNullable<App['workspace']['activeEditor']>['editor']> = {
    getCursor: () => castTo<EditorPosition>(cursor)
  };
  const activeEditor: null | StrictProxyPartial<App['workspace']['activeEditor']> = activeEditorOverrides
    ? {
      editor,
      ...filePath && { file: { path: filePath } }
    }
    : null;
  return strictProxy<App>({
    workspace: castTo<App['workspace']>({ activeEditor })
  });
}

function createSubstitutions(overrides?: SubstitutionsOverrides): Substitutions {
  return new Substitutions({
    actionContext: ActionContext.SaveAttachment,
    app: createApp(overrides?.activeEditorOverrides),
    ...overrides?.attachmentFileContent !== undefined && { attachmentFileContent: overrides.attachmentFileContent },
    ...overrides?.cursorLine !== undefined && { cursorLine: overrides.cursorLine },
    noteFilePath: overrides?.noteFilePath ?? 'folder/my-note.md',
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({}),
    ...overrides?.readAttachmentFileContent !== undefined && { readAttachmentFileContent: overrides.readAttachmentFileContent },
    tokenValidator: strictProxy<TokenValidator>({})
  });
}

function tk(inner: string): string {
  return `${DOLLAR}${OPEN_BRACE}${inner}${CLOSE_BRACE}`;
}

describe('Substitutions', () => {
  let errorSpy: MockInstance<typeof console.error>;

  beforeEach(() => {
    vi.clearAllMocks();
    Substitutions.registerCustomTokens('');
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    errorSpy.mockRestore();
    Substitutions.registerCustomTokens('');
  });

  describe('isRegisteredToken', () => {
    it('should return true for a built-in token (case-insensitive)', () => {
      expect(Substitutions.isRegisteredToken('NoteFileName')).toBe(true);
    });

    it('should return false for an unknown token', () => {
      expect(Substitutions.isRegisteredToken('unknownToken')).toBe(false);
    });
  });

  describe('registerCustomTokens', () => {
    it('should register a custom token provided via the registration script', () => {
      Substitutions.registerCustomTokens('registerCustomToken("myToken", () => "value");');
      expect(Substitutions.isRegisteredToken('myToken')).toBe(true);
    });

    it('should register only built-in tokens when the custom token script throws', () => {
      Substitutions.registerCustomTokens('throw new Error("boom");');
      expect(Substitutions.isRegisteredToken('noteFileName')).toBe(true);
      expect(mockPrintError).toHaveBeenCalled();
    });

    it('should reset to built-in tokens only when given an empty script', () => {
      Substitutions.registerCustomTokens('registerCustomToken("temp", () => "x");');
      Substitutions.registerCustomTokens('');
      expect(Substitutions.isRegisteredToken('temp')).toBe(false);
    });
  });

  describe('constructor', () => {
    it('should derive the note folder path from the note file path', () => {
      const substitutions = createSubstitutions({ noteFilePath: 'folder/note.md' });
      expect(substitutions.noteFolderPath).toBe('folder');
    });

    it('should treat a dot folder as an empty folder path', () => {
      const substitutions = createSubstitutions({ noteFilePath: 'note.md' });
      expect(substitutions.noteFolderPath).toBe('');
    });

    it('should read the cursor line from the active editor when it matches the note', () => {
      const substitutions = createSubstitutions({
        activeEditorOverrides: { cursor: { ch: 0, line: 5 }, filePath: 'note.md' },
        noteFilePath: 'note.md'
      });
      expect(substitutions.actionContext).toBe(ActionContext.SaveAttachment);
    });

    it('should keep the cursor line null when the active editor has no cursor', () => {
      const substitutions = createSubstitutions({
        activeEditorOverrides: { filePath: 'note.md' },
        noteFilePath: 'note.md'
      });
      expect(substitutions.actionContext).toBe(ActionContext.SaveAttachment);
    });

    it('should keep the cursor line null when the active editor file does not match', () => {
      const substitutions = createSubstitutions({
        activeEditorOverrides: { cursor: { ch: 0, line: 5 }, filePath: 'other.md' },
        noteFilePath: 'note.md'
      });
      expect(substitutions.noteFolderPath).toBe('');
    });

    it('should use an explicit cursor line when provided', () => {
      const substitutions = createSubstitutions({ cursorLine: 10, noteFilePath: 'note.md' });
      expect(substitutions.actionContext).toBe(ActionContext.SaveAttachment);
    });
  });

  describe('fillTemplate', () => {
    it('should leave a template without tokens unchanged', async () => {
      const result = await createSubstitutions().fillTemplate('plain-text');
      expect(result).toBe('plain-text');
    });

    it('should substitute a known token', async () => {
      const result = await createSubstitutions().fillTemplate(`prefix-${tk('noteFileName')}-suffix`);
      expect(result).toBe('prefix-my-note-suffix');
    });

    it('should substitute a token with a format object', async () => {
      const result = await createSubstitutions().fillTemplate(tk('noteFileName:{case:\'upper\'}'));
      expect(result).toBe('MY-NOTE');
    });

    it('should throw for an unknown token', async () => {
      await expect(createSubstitutions().fillTemplate(tk('unknownToken'))).rejects.toThrow('Unknown token \'unknownToken\'');
    });

    it('should throw when a token returns a non-string value', async () => {
      Substitutions.registerCustomTokens('registerCustomToken("nonString", () => 42);');
      await expect(createSubstitutions().fillTemplate(tk('nonString'))).rejects.toThrow('Token returned non-string value');
      expect(errorSpy).toHaveBeenCalledWith('Token returned non-string value.', expect.anything());
    });

    it('should report the template part to a token, defaulting to neither file name nor folder', async () => {
      Substitutions.registerCustomTokens('registerCustomToken("part", (ctx) => ctx.templatePart);');
      expect(await createSubstitutions().fillTemplate(tk('part'))).toBe(TemplatePart.Other);
      expect(await createSubstitutions().fillTemplate(tk('part'), TemplatePart.FileName)).toBe(TemplatePart.FileName);
      expect(await createSubstitutions().fillTemplate(tk('part'), TemplatePart.Folder)).toBe(TemplatePart.Folder);
    });

    it('should carry the template part into a nested fill', async () => {
      // A token reaching back through `ctx.fillTemplate` must not silently drop to the default —
      // This is the path `${prompt}` takes when it resolves its own `defaultValueTemplate`.
      Substitutions.registerCustomTokens(
        'registerCustomToken("part", (ctx) => ctx.templatePart);'
          + `registerCustomToken("nested", (ctx) => ctx.fillTemplate('${tk('part')}'));`
      );
      expect(await createSubstitutions().fillTemplate(tk('nested'), TemplatePart.FileName)).toBe(TemplatePart.FileName);
    });
  });

  describe('getAttachmentFileContent (via the attachmentFileSize token)', () => {
    it('should report 0 bytes when no attachment content is available', async () => {
      const result = await createSubstitutions().fillTemplate(tk('attachmentFileSize'));
      expect(result).toBe('0');
    });

    it('should read eager attachment content', async () => {
      const result = await createSubstitutions({ attachmentFileContent: new ArrayBuffer(2048) }).fillTemplate(tk('attachmentFileSize'));
      expect(result).toBe('2048');
    });

    it('should read attachment content lazily through the provider', async () => {
      const readAttachmentFileContent = vi.fn<() => Promise<ArrayBuffer>>().mockResolvedValue(new ArrayBuffer(1024));
      const result = await createSubstitutions({ readAttachmentFileContent }).fillTemplate(tk('attachmentFileSize'));
      expect(result).toBe('1024');
      expect(readAttachmentFileContent).toHaveBeenCalledOnce();
    });

    it('should read the content only once across multiple tokens', async () => {
      const readAttachmentFileContent = vi.fn<() => Promise<ArrayBuffer>>().mockResolvedValue(new ArrayBuffer(512));
      const result = await createSubstitutions({ readAttachmentFileContent })
        .fillTemplate(`${tk('attachmentFileSize')}-${tk('attachmentFileSize')}`);
      expect(result).toBe('512-512');
      expect(readAttachmentFileContent).toHaveBeenCalledOnce();
    });
  });
});
