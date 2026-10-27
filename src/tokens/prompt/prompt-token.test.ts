import type { App } from 'obsidian';

import { DUMMY_PATH } from '@mnaoumov/obsidian-lib/attachment-path';
import { castTo } from '@mnaoumov/typescript-lib/object-utils';
import { strictProxy } from '@mnaoumov/typescript-test-toolkit/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../../settings/plugin-settings-component.ts';
import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';
import type { TokenValidator } from '../token-validator.ts';

import { ActionContext } from '../token-evaluator-context.ts';
import { PromptToken } from './prompt-token.ts';
import { promptWithPreview } from './prompt-with-preview-modal.ts';

interface CreateContextParams {
  readonly actionContext: ActionContext;
  readonly attachmentFileName: string;
  readonly format: TokenEvaluatorContext['format'];
  readonly validatePath?: ValidatePathFunction;
}

interface PromptWithPreviewParams {
  readonly context: TokenEvaluatorContext;
  readonly defaultValue: string;
  readonly valueValidator: (value: string) => Promise<null | string>;
}

type ValidatePathFunction = TokenValidator['validatePath'];

vi.mock('./prompt-with-preview-modal.ts', () => ({
  promptWithPreview: vi.fn<(params: PromptWithPreviewParams) => Promise<null | string>>()
}));

const app = strictProxy<App>({});
const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({});

function createContext(params: CreateContextParams): TokenEvaluatorContext {
  const validatePath = vi.fn(params.validatePath ?? ((): Promise<string> => Promise.resolve('')));
  return castTo<TokenEvaluatorContext>({
    actionContext: params.actionContext,
    app,
    attachmentFileName: params.attachmentFileName,
    format: params.format,
    pluginSettingsComponent,
    tokenValidator: strictProxy<TokenValidator>({
      validatePath
    })
  });
}

beforeEach(() => {
  vi.mocked(promptWithPreview).mockReset();
});

describe('PromptToken', () => {
  it('should be named prompt', () => {
    const token = new PromptToken();
    expect(token.name).toBe('prompt');
  });

  it('should return the dummy path when validating tokens', async () => {
    const token = new PromptToken();
    const result = await token.evaluate(createContext({
      actionContext: ActionContext.ValidateTokens,
      attachmentFileName: 'image.png',
      format: null
    }));
    expect(result).toBe(DUMMY_PATH);
    expect(promptWithPreview).not.toHaveBeenCalled();
  });

  it('should return the dummy path when the attachment file name is the dummy path', async () => {
    const token = new PromptToken();
    const result = await token.evaluate(createContext({
      actionContext: ActionContext.SaveAttachment,
      attachmentFileName: DUMMY_PATH,
      format: null
    }));
    expect(result).toBe(DUMMY_PATH);
    expect(promptWithPreview).not.toHaveBeenCalled();
  });

  it('should prompt and format the result', async () => {
    vi.mocked(promptWithPreview).mockResolvedValue('My Value');
    const token = new PromptToken();
    const result = await token.evaluate(createContext({
      actionContext: ActionContext.SaveAttachment,
      attachmentFileName: 'image.png',
      format: { case: 'upper' }
    }));
    expect(result).toBe('MY VALUE');
  });

  it('should validate the prompted value through the context', async () => {
    const validatePath = vi.fn<ValidatePathFunction>(() => Promise.resolve('validation-error'));
    let capturedValidationResult: null | string = null;
    vi.mocked(promptWithPreview).mockImplementation(async (options) => {
      capturedValidationResult = await options.valueValidator('candidate');
      return 'result';
    });

    const token = new PromptToken();
    const result = await token.evaluate(createContext({
      actionContext: ActionContext.SaveAttachment,
      attachmentFileName: 'image.png',
      format: null,
      validatePath
    }));

    expect(result).toBe('result');
    expect(capturedValidationResult).toBe('validation-error');
    expect(validatePath).toHaveBeenCalledWith({
      areTokensAllowed: false,
      path: 'candidate'
    });
  });

  it('should throw when the prompt is cancelled', async () => {
    vi.mocked(promptWithPreview).mockResolvedValue(null);
    const token = new PromptToken();
    await expect(token.evaluate(createContext({
      actionContext: ActionContext.SaveAttachment,
      attachmentFileName: 'image.png',
      format: null
    }))).rejects.toThrow('Prompt cancelled');
  });
});
