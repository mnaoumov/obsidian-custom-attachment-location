import type { App } from 'obsidian';

import { castTo } from 'obsidian-dev-utils/object-utils';
import { DUMMY_PATH } from 'obsidian-dev-utils/obsidian/attachment-path';
import { strictProxy } from 'obsidian-dev-utils/strict-proxy';
import {
  beforeEach,
  describe,
  expect,
  it,
  vi
} from 'vitest';

import type { PluginSettingsComponent } from '../plugin-settings-component.ts';
import type { ValidatorValidatePathParams } from '../substitutions.ts';
import type { TokenEvaluatorContext } from '../token-evaluator-context.ts';

import { promptWithPreview } from '../prompt-with-preview-modal.ts';
import { ActionContext } from '../token-evaluator-context.ts';
import { PromptToken } from './prompt-token.ts';

interface CreateContextParams {
  readonly actionContext: ActionContext;
  readonly format: TokenEvaluatorContext['format'];
  readonly originalAttachmentFileName: string;
  validatePath?(params: ValidatorValidatePathParams): Promise<string>;
}

interface PromptWithPreviewParams {
  readonly ctx: TokenEvaluatorContext;
  readonly defaultValue: string;
  valueValidator(value: string): Promise<null | string>;
}

vi.mock('../prompt-with-preview-modal.ts', () => ({
  promptWithPreview: vi.fn<(params: PromptWithPreviewParams) => Promise<null | string>>()
}));

const app = strictProxy<App>({});
const pluginSettingsComponent = strictProxy<PluginSettingsComponent>({});

function createContext(params: CreateContextParams): TokenEvaluatorContext {
  return castTo<TokenEvaluatorContext>({
    actionContext: params.actionContext,
    app,
    format: params.format,
    originalAttachmentFileName: params.originalAttachmentFileName,
    pluginSettingsComponent,
    validatePath: vi.fn(params.validatePath ?? ((): Promise<string> => Promise.resolve('')))
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
      format: null,
      originalAttachmentFileName: 'image.png'
    }));
    expect(result).toBe(DUMMY_PATH);
    expect(promptWithPreview).not.toHaveBeenCalled();
  });

  it('should return the dummy path when the original attachment file name is the dummy path', async () => {
    const token = new PromptToken();
    const result = await token.evaluate(createContext({
      actionContext: ActionContext.SaveAttachment,
      format: null,
      originalAttachmentFileName: DUMMY_PATH
    }));
    expect(result).toBe(DUMMY_PATH);
    expect(promptWithPreview).not.toHaveBeenCalled();
  });

  it('should prompt and format the result', async () => {
    vi.mocked(promptWithPreview).mockResolvedValue('My Value');
    const token = new PromptToken();
    const result = await token.evaluate(createContext({
      actionContext: ActionContext.SaveAttachment,
      format: { case: 'upper' },
      originalAttachmentFileName: 'image.png'
    }));
    expect(result).toBe('MY VALUE');
  });

  it('should validate the prompted value through the context', async () => {
    const validatePath = vi.fn<(params: ValidatorValidatePathParams) => Promise<string>>(() => Promise.resolve('validation-error'));
    let capturedValidationResult: null | string = null;
    vi.mocked(promptWithPreview).mockImplementation(async (options) => {
      capturedValidationResult = await options.valueValidator('candidate');
      return 'result';
    });

    const token = new PromptToken();
    const result = await token.evaluate(createContext({
      actionContext: ActionContext.SaveAttachment,
      format: null,
      originalAttachmentFileName: 'image.png',
      validatePath
    }));

    expect(result).toBe('result');
    expect(capturedValidationResult).toBe('validation-error');
    expect(validatePath).toHaveBeenCalledWith({
      app,
      areTokensAllowed: false,
      path: 'candidate',
      pluginSettingsComponent
    });
  });

  it('should throw when the prompt is cancelled', async () => {
    vi.mocked(promptWithPreview).mockResolvedValue(null);
    const token = new PromptToken();
    await expect(token.evaluate(createContext({
      actionContext: ActionContext.SaveAttachment,
      format: null,
      originalAttachmentFileName: 'image.png'
    }))).rejects.toThrow('Prompt cancelled');
  });
});
