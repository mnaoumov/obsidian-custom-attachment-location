import type {
  App,
  EditorPosition
} from 'obsidian';
import type { PartialDeep } from 'type-fest';
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

import type { Plugin } from './plugin.ts';

import {
  parseCustomTokens,
  Substitutions,
  TokenValidationMode,
  validateFileName,
  validatePath
} from './substitutions.ts';
import { ActionContext } from './token-evaluator-context.ts';

vi.mock('obsidian-dev-utils/error', () => ({
  printError: vi.fn()
}));

interface ActiveEditorOverrides {
  cursor?: EditorPosition;
  filePath?: string;
}

const mockPrintError = vi.mocked(printError);

const DOLLAR = '$';
const OPEN_BRACE = '{';
const CLOSE_BRACE = '}';

function createPlugin(activeEditorOverrides?: ActiveEditorOverrides): Plugin {
  const cursor = activeEditorOverrides?.cursor;
  const filePath = activeEditorOverrides?.filePath;
  const editor: PartialDeep<NonNullable<App['workspace']['activeEditor']>['editor']> = {
    getCursor: () => castTo<EditorPosition>(cursor)
  };
  const activeEditor: null | PartialDeep<App['workspace']['activeEditor']> = activeEditorOverrides
    ? {
      editor,
      ...filePath ? { file: { path: filePath } } : {}
    }
    : null;
  const app: PartialDeep<App> = {
    workspace: { activeEditor }
  };

  return strictProxy<Plugin>({ app });
}

function tk(inner: string): string {
  return `${DOLLAR}${OPEN_BRACE}${inner}${CLOSE_BRACE}`;
}

describe('substitutions', () => {
  let warnSpy: MockInstance<typeof console.warn>;
  let errorSpy: MockInstance<typeof console.error>;

  beforeEach(() => {
    vi.clearAllMocks();
    Substitutions.registerCustomTokens('');
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
    errorSpy.mockRestore();
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

  describe('parseCustomTokens', () => {
    it('should parse and return custom tokens', () => {
      const tokens = parseCustomTokens('registerCustomToken("a", () => "1");');
      expect(tokens).not.toBeNull();
      expect(tokens).toHaveLength(1);
    });

    it('should return null and report an error when the script throws', () => {
      const tokens = parseCustomTokens('throw new Error("boom");');
      expect(tokens).toBeNull();
      expect(mockPrintError).toHaveBeenCalled();
    });
  });

  describe('constructor', () => {
    it('should derive note name and folder fields from the note file path', () => {
      const substitutions = new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        noteFilePath: 'folder/note.md',
        plugin: createPlugin()
      });
      expect(substitutions.noteFolderPath).toBe('folder');
    });

    it('should treat a dot folder as an empty folder name', () => {
      const substitutions = new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        noteFilePath: 'note.md',
        plugin: createPlugin()
      });
      expect(substitutions.noteFolderPath).toBe('');
    });

    it('should read the cursor line from the active editor when it matches the note', async () => {
      const plugin = createPlugin({ cursor: { ch: 0, line: 5 }, filePath: 'note.md' });
      const substitutions = new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        noteFilePath: 'note.md',
        plugin
      });
      const result = await substitutions.fillTemplate(`line${tk('noteFileName')}`);
      expect(result).toBe('linenote');
    });

    it('should keep the cursor line null when the active editor has no cursor', () => {
      const plugin = createPlugin({ filePath: 'note.md' });
      const substitutions = new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        noteFilePath: 'note.md',
        plugin
      });
      expect(substitutions.actionContext).toBe(ActionContext.SaveAttachment);
    });

    it('should keep the cursor line null when the active editor file does not match', () => {
      const plugin = createPlugin({ cursor: { ch: 0, line: 5 }, filePath: 'other.md' });
      const substitutions = new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        noteFilePath: 'note.md',
        plugin
      });
      expect(substitutions.noteFolderPath).toBe('');
    });

    it('should use an explicit cursor line when provided', () => {
      const substitutions = new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        cursorLine: 10,
        noteFilePath: 'note.md',
        plugin: createPlugin()
      });
      expect(substitutions.actionContext).toBe(ActionContext.SaveAttachment);
    });
  });

  describe('fillTemplate', () => {
    function createSubstitutions(): Substitutions {
      return new Substitutions({
        actionContext: ActionContext.SaveAttachment,
        noteFilePath: 'folder/my-note.md',
        plugin: createPlugin()
      });
    }

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
  });

  describe('validateFileName', () => {
    it('should reject tokens in Error mode', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('noteFileName'),
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Error
      });
      expect(message).toBe('Tokens are not allowed in file name');
    });

    it('should allow a clean name in Error mode', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'file',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Error
      });
      expect(message).toBe('');
    });

    it('should allow a clean name in Skip mode', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'file',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('');
    });

    it('should validate known tokens in Validate mode', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('noteFileName'),
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Validate
      });
      expect(message).toBe('');
    });

    it('should report a token whose format fails its schema in Validate mode', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('noteFileName:{case:\'invalid\'}'),
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Validate
      });
      expect(message).toContain('Invalid token');
    });

    it('should report a token whose format object is not valid JSON5 in Validate mode', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('noteFileName:{a:undefined}'),
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Validate
      });
      expect(message).toContain('Invalid format for token');
    });

    it('should report unknown tokens in Validate mode', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('unknownToken'),
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Validate
      });
      expect(message).toContain('Unknown token \'unknownToken\'');
    });

    it('should throw for an invalid validation mode', async () => {
      await expect(validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'file',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: castTo<TokenValidationMode>('Bogus')
      })).rejects.toThrow('Invalid token validation mode');
    });

    it('should return an error when the token syntax is invalid', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: `before${DOLLAR}${OPEN_BRACE}`,
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toContain('Invalid token syntax');
    });

    it('should allow single dots when configured', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: true,
        fileName: '.',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('');
    });

    it('should reject single dots when not allowed', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: '..',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('Single dots are not allowed in file name');
    });

    it('should allow an empty name when configured', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: '',
        isEmptyAllowed: true,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('');
    });

    it('should reject an empty name when not allowed', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: '',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('File name is empty');
    });

    it('should reject names containing OS-unsafe characters', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'a/b',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toContain('contains invalid symbols');
    });

    it('should reject names with more than two dots', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: '...',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toContain('more than two dots');
    });

    it('should reject names with trailing dots', async () => {
      const message = await validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'file.',
        isEmptyAllowed: false,
        plugin: createPlugin(),
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toContain('trailing dots');
    });
  });

  describe('validatePath', () => {
    it('should return empty for a valid path with allowed tokens', async () => {
      const message = await validatePath({
        areTokensAllowed: true,
        path: `folder/${tk('noteFileName')}`,
        plugin: createPlugin()
      });
      expect(message).toBe('');
    });

    it('should report an unknown token when tokens are allowed', async () => {
      const message = await validatePath({
        areTokensAllowed: true,
        path: tk('unknownToken'),
        plugin: createPlugin()
      });
      expect(message).toContain('Unknown token');
    });

    it('should reject tokens when tokens are not allowed', async () => {
      const message = await validatePath({
        areTokensAllowed: false,
        path: tk('noteFileName'),
        plugin: createPlugin()
      });
      expect(message).toBe('Tokens are not allowed in path');
    });

    it('should return empty for an empty path after trimming slashes', async () => {
      const message = await validatePath({
        areTokensAllowed: false,
        path: '/',
        plugin: createPlugin()
      });
      expect(message).toBe('');
    });

    it('should validate each path part and report the first error', async () => {
      const message = await validatePath({
        areTokensAllowed: false,
        path: 'good/bad.',
        plugin: createPlugin()
      });
      expect(message).toContain('trailing dots');
    });
  });
});
