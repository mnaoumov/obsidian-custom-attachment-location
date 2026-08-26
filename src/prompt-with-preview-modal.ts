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
import { CssClass } from 'obsidian-dev-utils/obsidian/css-class';
import { t } from 'obsidian-dev-utils/obsidian/i18n/i18n';
import { isSpellcheckEnabled } from 'obsidian-dev-utils/obsidian/obsidian-settings';
import { addPluginCssClasses } from 'obsidian-dev-utils/obsidian/plugin/plugin-context';
import { trashSafe } from 'obsidian-dev-utils/obsidian/vault';

import type { TokenEvaluatorContext } from './token-evaluator-context.ts';

import { selfWriteRegistry } from './self-write-registry.ts';
import { TemplatePart } from './token-evaluator-context.ts';

interface PromptWithPreviewModalConstructorParams {
  readonly context: TokenEvaluatorContext;
  readonly defaultValue: string;
  readonly promiseResolve: PromiseResolve<null | string>;
  valueValidator(this: void, value: string): Promise<null | string>;
}

interface PromptWithPreviewParams {
  readonly context: TokenEvaluatorContext;
  readonly defaultValue: string;
  valueValidator(this: void, value: string): Promise<null | string>;
}

class PreviewModal extends Modal {
  private embedComponent?: EmbedComponent;
  private temporaryFile?: TFile;

  public constructor(private readonly params: PromptWithPreviewParams) {
    super(params.context.app);
    addPluginCssClasses(this.containerEl, 'preview-modal');
  }

  public override onClose(): void {
    super.onClose();
    this.embedComponent?.unload();
    invokeAsyncSafely(async () => {
      if (this.temporaryFile) {
        await trashSafe(this.app, this.temporaryFile);
      }
    });
  }

  public override onOpen(): void {
    super.onOpen();
    invokeAsyncSafely(this.onOpenAsync.bind(this));
  }

  private async onOpenAsync(): Promise<void> {
    const embeddableCreator = this.app.embedRegistry.embedByExtension[this.params.context.originalAttachmentFileExtension];
    const attachmentFileContent = await this.params.context.getAttachmentFileContent();

    if (!embeddableCreator || !attachmentFileContent) {
      return;
    }

    const fullFileName = `${this.params.context.originalAttachmentFileName}.${this.params.context.originalAttachmentFileExtension}`;

    this.titleEl.setText(t(($) => $.promptWithPreviewModal.previewModal.title, { fullFileName }));

    const temporaryPath = `__temp${String(Date.now())}__${fullFileName}`;
    /*
     * Claimed so the externally-created-attachment handler does not treat this scratch file as an
     * attachment some other plugin just added — which would rename it and, with a `${prompt}`
     * template, open a second prompt on top of this one.
     */
    selfWriteRegistry.register(temporaryPath);
    this.temporaryFile = await this.app.vault.createBinary(temporaryPath, attachmentFileContent);

    const previewContainer = this.contentEl.createDiv('preview-container');

    this.embedComponent = embeddableCreator({
      app: this.app,
      containerEl: previewContainer
    }, this.temporaryFile);

    this.embedComponent.load();
    this.embedComponent.loadFile();
  }
}

class PromptWithPreviewModal extends Modal {
  private readonly context: TokenEvaluatorContext;
  private readonly defaultValue: string;
  private isOkClicked = false;
  private readonly promiseResolve: PromiseResolve<null | string>;

  private value = '';
  private readonly valueValidator: (this: void, value: string) => Promise<null | string>;

  public constructor(params: PromptWithPreviewModalConstructorParams) {
    super(params.context.app);
    this.context = params.context;
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

  /**
   * The heading (and input placeholder) names what the user is actually deciding. `${prompt}` is not
   * only a rename token — the same modal appears for a `${prompt}` in the attachment folder template,
   * where "Rename attachment file" would be plainly wrong (issue #59). Anything that is neither part
   * (e.g. the Markdown URL format) keeps the generic wording.
   */
  private getHeading(): string {
    switch (this.context.templatePart) {
      case TemplatePart.FileName: {
        return t(($) => $.promptWithPreviewModal.fileNameTitle);
      }
      case TemplatePart.Folder: {
        return t(($) => $.promptWithPreviewModal.folderTitle);
      }
      default: {
        return t(($) => $.promptWithPreviewModal.title);
      }
    }
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
    this.value = await this.context.fillTemplate(this.defaultValue);

    const heading = this.getHeading();

    const title = createFragment((f) => {
      f.appendText(heading);
      f.createEl('br');
      f.appendText(this.context.fullTemplate.slice(0, this.context.tokenStartOffset));
      f.createSpan({ cls: 'highlighted-token', text: this.context.tokenWithFormat });
      f.appendText(this.context.fullTemplate.slice(this.context.tokenEndOffset));
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
    textComponent.setPlaceholder(heading);
    inputEl.addClass(CssClass.TextBox);
    /*
     * `AbstractTextComponent` forces `spellcheck="false"` on every text component, so the vault
     * setting has to be re-applied here. Obsidian's own file explorer reads the same config when it
     * starts an inline rename.
     */
    inputEl.setAttribute('spellcheck', String(isSpellcheckEnabled(this.app)));
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

    const embeddableCreator = this.app.embedRegistry.embedByExtension[this.context.originalAttachmentFileExtension];
    const attachmentFileContent = await this.context.getAttachmentFileContent();

    if (!attachmentFileContent || !embeddableCreator) {
      previewButton.setDisabled(true);
    }

    /*
     * Focus LAST, once the whole modal is built. The input does not exist when `Modal` focuses its
     * first field — this modal fills its content in `onOpenAsync`, after `onOpen` has returned — so
     * the focus has to be explicit, unlike the upstream `obsidian-dev-utils` prompt, which builds
     * synchronously. It also has to come after the rest of the build: `reportValidity()` and the
     * button construction above both drop the focus if they run afterwards. `select()` then
     * pre-selects the default value, so typing replaces the name instead of appending to it
     * (issue #59).
     */
    inputEl.focus();
    inputEl.select();
  }

  private preview(): void {
    const previewModal = new PreviewModal({
      context: this.context,
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
