import type { EmbedComponent } from '@obsidian-typings/obsidian-public-latest';
import type { TFile } from 'obsidian';
import type { PromiseResolve } from 'obsidian-dev-utils/async';

import {
  ButtonComponent,
  Modal,
  TextComponent
} from 'obsidian';
import {
  convertAsyncToSync,
  invokeAsyncSafely
} from 'obsidian-dev-utils/async';
import { CssClass } from 'obsidian-dev-utils/css-class';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { addPluginCssClasses } from 'obsidian-dev-utils/obsidian/plugin/plugin-context';
import { trashSafe } from 'obsidian-dev-utils/obsidian/vault';

import type { TokenEvaluatorContext } from './token-evaluator-context.ts';

interface PromptWithPreviewModalConstructorParams {
  readonly ctx: TokenEvaluatorContext;
  readonly defaultValue: string;
  readonly promiseResolve: PromiseResolve<null | string>;
  valueValidator(this: void, value: string): Promise<null | string>;
}

interface PromptWithPreviewParams {
  readonly ctx: TokenEvaluatorContext;
  readonly defaultValue: string;
  valueValidator(this: void, value: string): Promise<null | string>;
}

class PreviewModal extends Modal {
  private embedComponent?: EmbedComponent;
  private tempFile?: TFile;

  public constructor(private readonly params: PromptWithPreviewParams) {
    super(params.ctx.app);
    addPluginCssClasses(this.containerEl, 'preview-modal');
  }

  public override onClose(): void {
    super.onClose();
    this.embedComponent?.unload();
    invokeAsyncSafely(async () => {
      if (this.tempFile) {
        await trashSafe(this.app, this.tempFile);
      }
    });
  }

  public override onOpen(): void {
    super.onOpen();
    invokeAsyncSafely(this.onOpenAsync.bind(this));
  }

  private async onOpenAsync(): Promise<void> {
    const embeddableCreator = this.app.embedRegistry.embedByExtension[this.params.ctx.originalAttachmentFileExtension];

    if (!embeddableCreator || !this.params.ctx.attachmentFileContent) {
      return;
    }

    const fullFileName = `${this.params.ctx.originalAttachmentFileName}.${this.params.ctx.originalAttachmentFileExtension}`;

    this.titleEl.setText(t(($) => $.promptWithPreviewModal.previewModal.title, { fullFileName }));

    const tempPath = `__temp${String(Date.now())}__${fullFileName}`;
    this.tempFile = await this.app.vault.createBinary(tempPath, this.params.ctx.attachmentFileContent);

    const previewContainer = this.contentEl.createDiv('preview-container');

    this.embedComponent = embeddableCreator({
      app: this.app,
      containerEl: previewContainer
    }, this.tempFile);

    this.embedComponent.load();
    this.embedComponent.loadFile();
  }
}

class PromptWithPreviewModal extends Modal {
  private readonly ctx: TokenEvaluatorContext;
  private readonly defaultValue: string;
  private isOkClicked = false;
  private readonly promiseResolve: PromiseResolve<null | string>;

  private value = '';
  private readonly valueValidator: (value: string) => Promise<null | string>;

  public constructor(params: PromptWithPreviewModalConstructorParams) {
    super(params.ctx.app);
    this.ctx = params.ctx;
    this.defaultValue = params.defaultValue;
    this.promiseResolve = params.promiseResolve;
    this.valueValidator = params.valueValidator;

    addPluginCssClasses(this.containerEl, CssClass.PromptModal);
  }

  public override onClose(): void {
    super.onClose();
    this.promiseResolve(this.isOkClicked ? this.value : null);
  }

  public override onOpen(): void {
    super.onOpen();
    invokeAsyncSafely(this.onOpenAsync.bind(this));
  }

  private handleOk(event: Event, textComponent: TextComponent): void {
    event.preventDefault();
    if (!textComponent.inputEl.checkValidity()) {
      return;
    }

    this.isOkClicked = true;
    this.close();
  }

  private async onOpenAsync(): Promise<void> {
    this.value = await this.ctx.fillTemplate(this.defaultValue);

    const title = createFragment((f) => {
      f.appendText(t(($) => $.promptWithPreviewModal.title));
      f.createEl('br');
      f.appendText(this.ctx.fullTemplate.slice(0, this.ctx.tokenStartOffset));
      f.createSpan({ cls: 'highlighted-token', text: this.ctx.tokenWithFormat });
      f.appendText(this.ctx.fullTemplate.slice(this.ctx.tokenEndOffset));
    });

    this.titleEl.setText(title);
    const textComponent = new TextComponent(this.contentEl);
    const inputEl = textComponent.inputEl;

    const validate = async (): Promise<void> => {
      const errorMessage = await this.valueValidator(inputEl.value) as string | undefined;
      inputEl.setCustomValidity(errorMessage ?? '');
      inputEl.reportValidity();
    };

    textComponent.setValue(this.value);
    textComponent.setPlaceholder(t(($) => $.promptWithPreviewModal.title));
    inputEl.addClass(CssClass.TextBox);
    textComponent.onChange((newValue) => {
      this.value = newValue;
    });
    inputEl.addEventListener('keydown', (event: KeyboardEvent) => {
      if (event.key === 'Enter') {
        this.handleOk(event, textComponent);
      } else if (event.key === 'Escape') {
        this.close();
      }
    });
    inputEl.addEventListener('input', convertAsyncToSync(validate));
    inputEl.addEventListener('focus', convertAsyncToSync(validate));
    invokeAsyncSafely(validate);
    const okButton = new ButtonComponent(this.contentEl);
    okButton.setButtonText(t(($) => $.obsidianDevUtils.buttons.ok));
    okButton.setCta();
    okButton.onClick((event) => {
      this.handleOk(event, textComponent);
    });
    okButton.setClass(CssClass.OkButton);
    const cancelButton = new ButtonComponent(this.contentEl);
    cancelButton.setButtonText(t(($) => $.obsidianDevUtils.buttons.cancel));
    cancelButton.onClick(this.close.bind(this));
    cancelButton.setClass(CssClass.CancelButton);

    const previewButton = new ButtonComponent(this.contentEl);
    previewButton.setButtonText(t(($) => $.buttons.previewAttachmentFile));
    previewButton.onClick(this.preview.bind(this));

    const embeddableCreator = this.app.embedRegistry.embedByExtension[this.ctx.originalAttachmentFileExtension];

    if (!this.ctx.attachmentFileContent || !embeddableCreator) {
      previewButton.setDisabled(true);
    }
  }

  private preview(): void {
    const previewModal = new PreviewModal({
      ctx: this.ctx,
      defaultValue: this.defaultValue,
      valueValidator: this.valueValidator
    });
    previewModal.open();
  }
}

export function promptWithPreview(params: PromptWithPreviewParams): Promise<null | string> {
  return new Promise((promiseResolve) => {
    const modal = new PromptWithPreviewModal({
      ...params,
      promiseResolve
    });
    modal.open();
  });
}
