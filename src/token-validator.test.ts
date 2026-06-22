import type { App } from 'obsidian';

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

import { Substitutions } from './substitutions.ts';
import {
  TokenValidationMode,
  TokenValidator
} from './token-validator.ts';

vi.mock('obsidian-dev-utils/error', () => ({
  printError: vi.fn<(error: unknown) => void>()
}));

const DOLLAR = '$';
const OPEN_BRACE = '{';
const CLOSE_BRACE = '}';

function createTokenValidator(): TokenValidator {
  const app = strictProxy<App>({
    workspace: castTo<App['workspace']>({ activeEditor: null })
  });
  return new TokenValidator({
    app,
    pluginSettingsComponent: strictProxy<PluginSettingsComponent>({})
  });
}

function tk(inner: string): string {
  return `${DOLLAR}${OPEN_BRACE}${inner}${CLOSE_BRACE}`;
}

describe('TokenValidator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Substitutions.registerCustomTokens('');
  });

  afterEach(() => {
    Substitutions.registerCustomTokens('');
  });

  describe('validateFileName', () => {
    it('should reject tokens in Error mode', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('noteFileName'),
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Error
      });
      expect(message).toBe('Tokens are not allowed in file name');
    });

    it('should allow a clean name in Error mode', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'file',
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Error
      });
      expect(message).toBe('');
    });

    it('should allow a clean name in Skip mode', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'file',
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('');
    });

    it('should validate known tokens in Validate mode', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('noteFileName'),
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Validate
      });
      expect(message).toBe('');
    });

    it('should report a token whose format fails its schema in Validate mode', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('noteFileName:{case:\'invalid\'}'),
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Validate
      });
      expect(message).toContain('Invalid token');
    });

    it('should report a token whose format object is not valid JSON5 in Validate mode', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('noteFileName:{a:undefined}'),
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Validate
      });
      expect(message).toContain('Invalid format for token');
    });

    it('should report unknown tokens in Validate mode', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: tk('unknownToken'),
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Validate
      });
      expect(message).toContain('Unknown token \'unknownToken\'');
    });

    it('should throw for an invalid validation mode', async () => {
      await expect(
        createTokenValidator().validateFileName({
          areSingleDotsAllowed: false,
          fileName: 'file',
          isEmptyAllowed: false,
          tokenValidationMode: castTo<TokenValidationMode>('Bogus')
        })
      ).rejects.toThrow('Invalid token validation mode');
    });

    it('should return an error when the token syntax is invalid', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: `before${DOLLAR}${OPEN_BRACE}`,
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toContain('Invalid token syntax');
    });

    it('should allow single dots when configured', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: true,
        fileName: '.',
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('');
    });

    it('should reject single dots when not allowed', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: '..',
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('Single dots are not allowed in file name');
    });

    it('should allow an empty name when configured', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: '',
        isEmptyAllowed: true,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('');
    });

    it('should reject an empty name when not allowed', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: '',
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toBe('File name is empty');
    });

    it('should reject names containing OS-unsafe characters', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'a/b',
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toContain('contains invalid symbols');
    });

    it('should reject names with more than two dots', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: '...',
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toContain('more than two dots');
    });

    it('should reject names with trailing dots', async () => {
      const message = await createTokenValidator().validateFileName({
        areSingleDotsAllowed: false,
        fileName: 'file.',
        isEmptyAllowed: false,
        tokenValidationMode: TokenValidationMode.Skip
      });
      expect(message).toContain('trailing dots');
    });
  });

  describe('validatePath', () => {
    it('should return empty for a valid path with allowed tokens', async () => {
      const message = await createTokenValidator().validatePath({
        areTokensAllowed: true,
        path: `folder/${tk('noteFileName')}`
      });
      expect(message).toBe('');
    });

    it('should report an unknown token when tokens are allowed', async () => {
      const message = await createTokenValidator().validatePath({
        areTokensAllowed: true,
        path: tk('unknownToken')
      });
      expect(message).toContain('Unknown token');
    });

    it('should reject tokens when tokens are not allowed', async () => {
      const message = await createTokenValidator().validatePath({
        areTokensAllowed: false,
        path: tk('noteFileName')
      });
      expect(message).toBe('Tokens are not allowed in path');
    });

    it('should return empty for an empty path after trimming slashes', async () => {
      const message = await createTokenValidator().validatePath({
        areTokensAllowed: false,
        path: '/'
      });
      expect(message).toBe('');
    });

    it('should validate each path part and report the first error', async () => {
      const message = await createTokenValidator().validatePath({
        areTokensAllowed: false,
        path: 'good/bad.'
      });
      expect(message).toContain('trailing dots');
    });
  });
});
