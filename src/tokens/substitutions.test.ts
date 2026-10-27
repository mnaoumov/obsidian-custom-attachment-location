import type { StrictProxyPartial } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import type {
  App,
  EditorPosition
} from 'obsidian';
import type { MockInstance } from 'vitest';

import { printError } from '@mnaoumov/typescript-lib/error';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../settings/plugin-settings-component.ts';
import type { TokenValidator } from './token-validator.ts';

import { Substitutions } from './substitutions.ts';
import {
  ActionContext,
  TemplatePart
} from './token-evaluator-context.ts';
import { LegacyTokenSyntaxError } from './token-parser.ts';

vi.mock('@mnaoumov/typescript-lib/error', () => ({
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
  readAttachmentFileContent?: () => Promise<ArrayBuffer>;
}

const mockPrintError = vi.mocked(printError);

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
  return `{{${inner}}}`;
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

  describe('ensureCustomTokensRegistered', () => {
    it('should register custom tokens that differ from the ones registered last', () => {
      Substitutions.ensureCustomTokensRegistered('registerCustomToken("fresh", () => "x");');
      expect(Substitutions.isRegisteredToken('fresh')).toBe(true);
    });

    it('should not run the code again when it is the code registered last', () => {
      const code = 'window.__ensureCount = (window.__ensureCount ?? 0) + 1;';
      const globalRecord = castTo<Record<string, unknown>>(window);
      try {
        Substitutions.registerCustomTokens(code);
        Substitutions.ensureCustomTokensRegistered(code);
        expect(globalRecord['__ensureCount']).toBe(1);
      } finally {
        delete globalRecord['__ensureCount'];
      }
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
      // this is the path `{{prompt}}` takes when it resolves its own `defaultValueTemplate`.
      Substitutions.registerCustomTokens(
        'registerCustomToken("part", (ctx) => ctx.templatePart);'
          + `registerCustomToken("nested", (ctx) => ctx.fillTemplate('${tk('part')}'));`
      );
      expect(await createSubstitutions().fillTemplate(tk('nested'), TemplatePart.FileName)).toBe(TemplatePart.FileName);
    });

    it('should hand a date token the scalar format shorthand as its moment.js format', async () => {
      expect(await createSubstitutions().fillTemplate(tk('date:[constant]'))).toBe('constant');
    });

    it('should hand a custom token the scalar format as the text itself', async () => {
      Substitutions.registerCustomTokens('registerCustomToken("echo", (ctx) => typeof ctx.format + ":" + ctx.format);');
      expect(await createSubstitutions().fillTemplate(tk('echo:some text'))).toBe('string:some text');
    });

    it('should reject the scalar format shorthand for a token whose format is an object', async () => {
      await expect(createSubstitutions().fillTemplate(tk('noteFileName:upper'))).rejects.toThrow();
    });

    /* eslint-disable no-template-curly-in-string -- The retired `${...}` plugin token syntax, not JS template literals. */
    it('should fail loudly on a token in the retired syntax instead of leaving it as text', async () => {
      await expect(createSubstitutions().fillTemplate('./assets/${noteFileName}')).rejects.toThrow(LegacyTokenSyntaxError);
      await expect(createSubstitutions().fillTemplate('./assets/${noteFileName}')).rejects.toThrow(
        'Write it as \'{{noteFileName}}\' instead.'
      );
    });

    it('should fail loudly on a retired-syntax template a custom token fills', async () => {
      Substitutions.registerCustomTokens('registerCustomToken("stale", (ctx) => ctx.fillTemplate(\'${noteFileName}\'));');
      await expect(createSubstitutions().fillTemplate(tk('stale'))).rejects.toThrow(LegacyTokenSyntaxError);
    });
    /* eslint-enable no-template-curly-in-string -- The retired `${...}` plugin token syntax, not JS template literals. */
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

describe('Substitutions, original and current attachment names', () => {
  function createNameSubstitutions(params: Pick<ConstructorParameters<typeof Substitutions>[0], 'attachmentFileName' | 'onOriginalAttachmentFileNameUnknown' | 'originalAttachmentFileName'>): Substitutions {
    return new Substitutions({
      actionContext: ActionContext.CollectAttachments,
      app: createApp(),
      noteFilePath: 'folder/my-note.md',
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({}),
      tokenValidator: strictProxy<TokenValidator>({}),
      ...params
    });
  }

  beforeEach(() => {
    Substitutions.registerCustomTokens('');
  });

  it('should read the current name and the arrival name separately', async () => {
    const substitutions = createNameSubstitutions({ attachmentFileName: 'my-note-img.jpg', originalAttachmentFileName: 'img.png' });

    expect(await substitutions.fillTemplate(`${tk('attachmentFileName')}.${tk('attachmentFileExtension')}`)).toBe('my-note-img.jpg');
    expect(await substitutions.fillTemplate(`${tk('originalAttachmentFileName')}.${tk('originalAttachmentFileExtension')}`)).toBe('img.png');
  });

  it('should let either name stand in for the other when only one is given', async () => {
    expect(await createNameSubstitutions({ attachmentFileName: 'a.png' }).fillTemplate(tk('originalAttachmentFileName'))).toBe('a');
    expect(await createNameSubstitutions({ originalAttachmentFileName: 'b.png' }).fillTemplate(tk('attachmentFileName'))).toBe('b');
  });

  it('should report an unknown original once, and only when a template reads it', async () => {
    const onOriginalAttachmentFileNameUnknown = vi.fn<() => void>();
    const substitutions = createNameSubstitutions({ attachmentFileName: 'img.png', onOriginalAttachmentFileNameUnknown });

    expect(await substitutions.fillTemplate(tk('attachmentFileName'))).toBe('img');
    expect(onOriginalAttachmentFileNameUnknown).not.toHaveBeenCalled();

    expect(await substitutions.fillTemplate(`${tk('originalAttachmentFileName')}-${tk('originalAttachmentFileExtension')}`)).toBe('img-png');
    expect(await substitutions.fillTemplate(tk('originalAttachmentFileName'))).toBe('img');
    expect(onOriginalAttachmentFileNameUnknown).toHaveBeenCalledOnce();
  });

  it('should report an unknown original when the extension is the first thing read', async () => {
    const onOriginalAttachmentFileNameUnknown = vi.fn<() => void>();
    const substitutions = createNameSubstitutions({ attachmentFileName: 'img.png', onOriginalAttachmentFileNameUnknown });

    expect(await substitutions.fillTemplate(tk('originalAttachmentFileExtension'))).toBe('png');
    expect(onOriginalAttachmentFileNameUnknown).toHaveBeenCalledOnce();
  });

  it('should never report when the original is known', async () => {
    const onOriginalAttachmentFileNameUnknown = vi.fn<() => void>();
    const substitutions = createNameSubstitutions({ attachmentFileName: 'x.png', onOriginalAttachmentFileNameUnknown, originalAttachmentFileName: 'img.png' });

    expect(await substitutions.fillTemplate(tk('originalAttachmentFileName'))).toBe('img');
    expect(onOriginalAttachmentFileNameUnknown).not.toHaveBeenCalled();
  });

  it('should keep the file dates under both token names', async () => {
    const substitutions = new Substitutions({
      actionContext: ActionContext.CollectAttachments,
      app: createApp(),
      attachmentFileStats: { ctime: Date.UTC(2020, 0, 2), mtime: Date.UTC(2021, 0, 2), size: 0 },
      noteFilePath: 'folder/my-note.md',
      pluginSettingsComponent: strictProxy<PluginSettingsComponent>({}),
      tokenValidator: strictProxy<TokenValidator>({})
    });

    expect(await substitutions.fillTemplate(tk('attachmentFileCreationDate:YYYY'))).toBe(await substitutions.fillTemplate(tk('originalAttachmentFileCreationDate:YYYY')));
    expect(await substitutions.fillTemplate(tk('attachmentFileModificationDate:YYYY'))).toBe(await substitutions.fillTemplate(tk('originalAttachmentFileModificationDate:YYYY')));
  });
});
