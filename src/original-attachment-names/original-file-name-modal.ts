/**
 * @file
 *
 * The dialog behind `Show original file name`.
 *
 * It shows the name an attachment arrived with in a read-only box the user can select, and a copy button beside it, so
 * the user sees the value before anything reaches the clipboard.
 */

import type { PluginNoticeComponent } from '@mnaoumov/obsidian-lib/components/plugin-notice-component';
import type { PromiseResolve } from '@mnaoumov/typescript-lib/async';
import type { App } from 'obsidian';

import { t } from '@mnaoumov/obsidian-lib/i18n/i18n';
import {
  ModalBase,
  showModal
} from '@mnaoumov/obsidian-lib/modals/modal';
import { addPluginCssClasses } from '@mnaoumov/obsidian-lib/plugin/plugin-context';
import { convertAsyncToSync } from '@mnaoumov/typescript-lib/async';
import {
  ButtonComponent,
  ExtraButtonComponent,
  TextComponent
} from 'obsidian';

/**
 * Parameters for {@link copyOriginalFileName}.
 */
export interface CopyOriginalFileNameParams {
  /**
   * The name to copy.
   */
  readonly originalFileName: string;

  /**
   * Shows the copy notices, naming the plugin.
   */
  readonly pluginNoticeComponent: PluginNoticeComponent;
}

/**
 * Parameters for {@link showOriginalFileNameModal}.
 */
export interface ShowOriginalFileNameModalParams {
  /**
   * An Obsidian app instance.
   */
  readonly app: App;

  /**
   * The current path of the attachment, named in the dialog.
   */
  readonly attachmentPath: string;

  /**
   * The name the attachment arrived with.
   */
  readonly originalFileName: string;

  /**
   * Shows the copy notices, naming the plugin.
   */
  readonly pluginNoticeComponent: PluginNoticeComponent;
}

interface OriginalFileNameModalConstructorParams extends ShowOriginalFileNameModalParams {
  readonly promiseResolve: PromiseResolve<void>;
}

class OriginalFileNameModal extends ModalBase<void> {
  private readonly attachmentPath: string;
  private readonly originalFileName: string;
  private readonly pluginNoticeComponent: PluginNoticeComponent;

  public constructor(params: OriginalFileNameModalConstructorParams) {
    super(params);
    this.attachmentPath = params.attachmentPath;
    this.originalFileName = params.originalFileName;
    this.pluginNoticeComponent = params.pluginNoticeComponent;
    addPluginCssClasses(this.containerEl, 'original-file-name-modal');
  }

  public override onClose(): void {
    this.promiseResolve();
  }

  public override onOpen(): void {
    this.titleEl.setText(t(($) => $.originalAttachmentNames.originalFileNameModal.title));
    this.contentEl.createEl('p', { text: t(($) => $.originalAttachmentNames.originalFileNameModal.description, { path: this.attachmentPath }) });

    const valueEl = this.contentEl.createDiv('original-file-name-value');
    const textComponent = new TextComponent(valueEl).setValue(this.originalFileName);
    textComponent.inputEl.readOnly = true;
    textComponent.inputEl.addEventListener('focus', () => {
      textComponent.inputEl.select();
    });

    new ExtraButtonComponent(valueEl)
      .setIcon('copy')
      .setTooltip(t(($) => $.originalAttachmentNames.originalFileNameModal.copy))
      .onClick(convertAsyncToSync(this.copy.bind(this)));

    const buttonsEl = this.contentEl.createDiv('modal-button-container');
    new ButtonComponent(buttonsEl)
      .setButtonText(t(($) => $.originalAttachmentNames.originalFileNameModal.close))
      .setCta()
      .onClick(this.close.bind(this));
  }

  private async copy(): Promise<void> {
    await copyOriginalFileName({
      originalFileName: this.originalFileName,
      pluginNoticeComponent: this.pluginNoticeComponent
    });
  }
}

/**
 * Copies an original file name to the clipboard and says so in a notice, or says the copy failed.
 *
 * Shared by the dialog's copy button and the `Copy original file name` command.
 *
 * @param params - The name and the notice component.
 */
export async function copyOriginalFileName(params: CopyOriginalFileNameParams): Promise<void> {
  try {
    await activeWindow.navigator.clipboard.writeText(params.originalFileName);
  } catch (error) {
    console.error('Failed to copy the original file name to the clipboard.', error);
    params.pluginNoticeComponent.showNotice(t(($) => $.originalAttachmentNames.originalFileNameModal.copyFailed));
    return;
  }
  params.pluginNoticeComponent.showNotice(t(($) => $.originalAttachmentNames.originalFileNameModal.copiedNotice, { name: params.originalFileName }));
}

/**
 * Shows the name an attachment arrived with, in a read-only box with a copy button.
 *
 * @param params - The attachment, its original name and the app.
 * @returns A {@link Promise} that resolves when the dialog closes.
 */
export async function showOriginalFileNameModal(params: ShowOriginalFileNameModalParams): Promise<void> {
  await showModal((promiseResolve: PromiseResolve<void>) =>
    new OriginalFileNameModal({
      ...params,
      promiseResolve
    })
  );
}
